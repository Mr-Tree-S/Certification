# Cortex

## Study Approach

1. Read PSE Cortex Professional Study Guide
2. Check RUSH
3. Open Source Questions
   - <https://free-braindumps.com/palo-alto-networks/free-pse-cortex-braindumps.html>
   - <https://vceguide.com/palo-alto-networks-certification/>

---

## **PSE Cortex Professional Study Guide**

## **RUSH**

### XDR

#### 2

What allows the use of predetermined Palo Alto Networks roles to assign access rights to Cortex XDR users?

- a. Restrictions security profile
- b. Cloud identity engine (CIE)
- c. Endpoint groups
- d. role-based access control (RBAC)

#### 5

Which two types of Indicators of compromise (IOCs) are available for creation in Cortex XDR?

- a. Internet Protocol (IP)
- b. Endpoint hostname
- c. registry entry
- d. domain

#### 7

Which component displays an entire picture of an attack, including the root cause or delivery point?

- a. Cortex XSOAR Work Plan
- b. Cortex Data Lake
- c. Cortex XDR Causality View
- d. Cortex SOC Orchestrator

#### 8

Which two items are stitched to the Cortex XDR causality chain? (Choose two.)

- a. registry set value
- b. firewall alerts
- c. security and information event management (SIEM)
- d. full uniform resource locator (URL)

#### 12

What is the result of creating an exception from an exploit security event?

- a. Triggered exploit protection module (EPM) for the host and process involved is disabled
- b. User is exempt from generating events for 24 hours
- c. Process from WildFire analysis is whitelisted
- d. Administrators are exempt from generating alerts for 24 hours

#### 15

Cortex XDR external data ingestion processes ingest data from which sources?

- a. Windows event logs only
- b. Windows event logs, syslogs, and custom external sources
- c. Windows event logs and syslogs only
- d. Syslogs only

#### 16 X

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

#### 18

An adversary attempts to communicate with malware running on a network in order to control malware activities or to exfiltrate data from the network.

What Cortex XDR Analytics alert will this activity most likely trigger?

- a. Uncommon local scheduled task creation
- b. Malware
- c. New administrative behavior
- d. DNS Tunneling

#### 19

Which two types of indicators of compromise (IOCs) are available for creation in Cortex XDR?

- a. Registry
- b. Hostname
- c. Hash
- d. File path

#### 25 X

A Cortex XDR Pro administrator is alerted to a suspicious process creation security event from multiple users who believe these events are false positives.

Which two steps should be taken confirm the false positives and create an exception? (Choose two)

- a. In the Cortex XDR security event, review the specific parent process, child process, and command line arguments
- b. Contact support and ask for a security exception
- c. Within the Malware Security profile, add the specific parent process, child process, and
command line argument to the child process whitelist
- d. Within the Malware Security profile, disable the Prevent Malicious Child Process Execution module

```text
这个问题询问的是，Cortex XDR Pro管理员在收到多个用户报告疑似虚报的进程创建安全事件的情况下，应该采取哪两个步骤来确认虚报并创建异常情况。现在让我详细解释每个选项：
a. In the Cortex XDR security event, review the specific parent process, child process, and command line arguments (在Cortex XDR安全事件中，审查特定的父进程、子进程和命令行参数)：
这个选项建议管理员在Cortex XDR安全事件中审查详细的信息，包括父进程、子进程和命令行参数。通过仔细审查这些详细信息，可以帮助管理员确认安全事件是否是虚报（误报）还是合法的安全问题。这一步骤有助于了解事件的实际情况。
b. Contact support and ask for a security exception (联系支持部门并请求安全异常)：
这个选项建议管理员联系支持部门，请求创建一个安全异常来处理已确认的虚报事件。支持团队可以协助管理员完成创建异常的过程，以防止这些事件再次触发未来的警报。
选项c建议将特定的进程和命令行参数添加到子进程白名单中，但问题没有提到这一步骤的必要性或适用性，因此不能确定它是否正确。
选项d建议禁用“Prevent Malicious Child Process Execution”模块，但这应该谨慎进行，并且仅在确定该模块导致虚报时才应采取。禁用安全模块可能会增加潜在威胁，因此应该在必要时才使用。
综上所述，正确的步骤是选择选项a和b，即审查事件详细信息以确认虚报，并联系支持部门请求创建安全异常来处理已确认的虚报事件。其他选项可能在某些情况下有用，但它们的使用需要更多的谨慎和确凿的证据。
```

#### 26 X

The Cortex XDR management service requires which other Palo Alto Networks product?

- a. Cortex Data Lake
- b. Directory Sync
- c. Panorama
- d. Cortex XSOAR

```text
a. Cortex Data Lake:
Cortex Data Lake 是Palo Alto Networks的一个产品，它提供了大规模的数据存储和分析能力，用于支持各种安全产品的操作。虽然它与Cortex XDR相关，但Cortex XDR管理服务并不直接依赖于Cortex Data Lake。它们可以协同工作，但并不是必需的。
b. Directory Sync:
Directory Sync 是用于将活动目录（Active Directory）与Palo Alto Networks安全产品集成的工具。虽然它在身份认证和访问控制方面非常重要，但它也不是Cortex XDR管理服务的直接要求。
c. Panorama:
这是正确答案。Panorama 是Palo Alto Networks的集中式管理平台，用于管理和监视各种Palo Alto Networks安全产品，包括Cortex XDR。它允许管理员集中管理安全策略、配置和设备，是Cortex XDR管理服务的关键组件之一。
d. Cortex XSOAR:
Cortex XSOAR是Palo Alto Networks的自动化和响应平台，用于协调安全事件响应和工作流。它可以与Cortex XDR集成，但不是Cortex XDR管理服务的直接要求。
综上所述，正确答案是选项c，即Cortex XDR管理服务需要Palo Alto Networks的Panorama来提供集中化的管理和监视功能。其他选项是相关的Palo Alto Networks产品或组件，但它们不是Cortex XDR管理服务的必需组件。
```

#### 27

Which Cortex XDR agent capability prevents loading malicious files from USB-connected removable equipment?

- a. Device control
- b. Agent management
- c. Agent configuration
- d. Device customization

#### 29 X

Which two methods does the Cortex XDR agent use to identify malware during a scheduled scan? (Choose two)

- a. WildFire hash comparison
- b. Signature comparison
- c. Dynamic analysis
- d. Heuristic analysis

```text
a. WildFire hash comparison
选的理由：Cortex XDR代理会使用WildFire服务的信息库，比较文件的哈希值，检查它们是否与已知的恶意软件样本匹配。这是一个快速且有效的检测方式，因为已知的恶意软件哈希值可以轻松地与大量的文件进行比较。
不选的理由：没有明显的不选理由，因为这是Cortex XDR代理在进行扫描时常用的检测方法。
b. Signature comparison
选的理由：传统的杀毒软件和反恶意软件工具经常使用签名比较来检测已知的恶意软件。它们依赖于已知的恶意软件签名数据库。
不选的理由：Cortex XDR不仅仅依赖于传统的签名比较。相比之下，它更倾向于使用如WildFire哈希值比较和启发式分析等更先进的方法。所以，虽然签名比较可能是其组件之一，但不是主要的检测方法。
c. Dynamic analysis
选的理由：动态分析涉及到在受控环境中执行文件或代码，以观察其行为。这是WildFire的一部分功能，可以用来识别未知的恶意软件。
不选的理由：在定期扫描中，动态分析可能不是主要使用的方法。动态分析通常需要更多的时间和资源，而定期扫描通常侧重于更快速的检测方法。
d. Heuristic analysis
选的理由：启发式分析是基于文件的特征和行为模式来评估其是否为恶意的。这种分析不仅仅基于已知的恶意软件签名，而是查找与恶意软件相关的特定行为或属性。这使Cortex XDR能够识别尚未被明确定义为已知恶意软件的潜在威胁。
不选的理由：没有明显的不选理由，因为这是Cortex XDR在进行扫描时的核心检测方法之一。
根据上述分析，答案选项a（WildFire hash comparison）和d（Heuristic analysis）是Cortex XDR代理在定期扫描中主要使用的方法。
```

#### 32

Which two areas of Cortex XDR are used for threat hunting activities? (Choose two)

- a. Host insights module
- b. Indicators of compromise (IOC) rules
- c. Live terminal
- d. Query builder

#### 33

Which two entities can be created as a behavioral indicator of compromise (BIOC)? (Choose two)

- a. Network
- b. Event alert
- c. Data
- d. process

> <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Create-a-BIOC-Rule>

#### 34 X

Which statement applies to the malware protection flow in Cortex XDR Prevent?

- a. Hash comparisons come after local static analysis
- b. In the final step, the block list is verified
- c. Local static analysis happens before a WildFire verdict check
- d. A trusted signed file is exempt from local static analysis

#### 43

A customer has purchased Cortex Data Lake storage with the following configuration, which requires 2 TB of Cortex Data Lake to order:

- Support for 300 total Cortex XDR clients all forwarding Cortex XDR data with 30-day retention
- Storage for higher fidelity logs to support Cortex XDR advanced analytics

The customer now needs 1000 total Cortex XDR clients, but continues with 300 clients forwarding Cortex XDR data with 30-day retention.

What is the new total storage requirement for Cortex Data Lake storage to order?
a. 4TB b. 10TB c. 8TB d. 2TB

#### 45

Which Cortex XDR license is required for a customer that requests endpoint detection and response (EDR) data collection capabilities?

- a. Cortex XDR Prevent
- b. Cortex XDR Pro Per Endpoint
- c. Cortex XDR Endpoint
- d. Cortex XDR Pro per TB

#### 46

Where can all the relevant incidents for an indicator be viewed?

- a. Linked indicators column in incident screen
- b. Linked incidents column in indicator screen
- c. Related incidents column in indicator screen
- d. Related indicators column in incident screen

#### 47 X

Which type of log is ingested natively in Cortex XDR Pro per TB?

- a. Docker
- b. Microsoft Office 365
- c. Demisto
- d. Google Kubernetes Engine

#### 49 X

What are two reasons incident investigation is needed in Cortex XDR? (Choose two)

- a. Insider Threats may not be blocked and initial activity may go undetected
- b. Detailed reports are needed for senior management to justify the cost of XDR
- c. No solution will stop every attack requiring further investigation of activity
- d. Analyst need to acquire forensic artifacts of malware that has been blocked by the XDR agent

#### 52

Which two filter operators are available in Cortex XDR? (Choose two)

- a. =
- b. Contains
- c. Is Contained By
- d. <>

#### 55

When initiated, which Cortex XDR capability allows immediate termination of the process or whole process tree on an anomalous process discovered during investigation of a security event?

- a. Live sensors
- b. File explorer
- c. Live terminal
- d. Log stitching

#### 56

Which statement applies to the differentiation of Cortex XDR from security information and event management (SIEM)?

- a. SIEM has been entirely designed and built as cloud-native, with the ability to stitch together cloud logs, on-premises logs, third-party logs, and endpoint logs
- b. Cortex XDR allows just logging into the console and out of the box the events were blocked as a proactive approach
- c. Cortex XDR requires a large and diverse team of analysts and up to several weeks for simple actions like creating an alert
- d. SIEM has access to raw logs from agents, where Cortex XDR traditionally only gets alerts

### XSOAR

#### 1

A Cortex XSOAR customer wants to ingest from a single mailbox. The mailbox brings in reported phishing emails and email requests from human resources (HR) to onboard new users. The customer wants to run two separate workflows from this mailbox, one for phishing and one for onboarding.

What will allow Cortex XSOAR to accomplish this in the most efficient way?

- a. Use machine learning (ML) to determine incident type
- b. Create two instances of the email integration and classily one instance as ingesting
incidents of type phishing and the other as ingesting incidents of type boarding
- c. Use an incident classifier based on field in each type of email to classify those containing
“Phish Alert” in the subject as phishing and those containing “Onboard Request” as
onboarding
- d. Create a playbook to process and determine incident type based on content of the email

#### 3

What integration allows searching and displaying Splunk results within Cortex XSOAR?

- a. Demisto App for Splunk integration
- b. SplunkPY integration
- c. Splunk integration
- d. XSOAR REST API integration

#### 4

How can Cortex XSOAR save time when a phishing incident occurs?

- a. It can automatically identify every mailbox that received the phish and create
corresponding cases for them
- b. It can automatically email staff to warn them about the phishing attack and show them a copy of the email
- c. It can automatically purge the email from user mailboxes in which it has not yet opened
- d. It can automatically respond to the phishing email to unsubscribe from future emails

#### 6

Which command is used to add Cortex XSOAR “User1” to an investigation from the War Room?

- a. #Invite User1
- b. @User1
- c. #User1
- d. !Invite User1

#### 9

A customer wants the main Cortex XSOAR server installed in one site and wants to integrate with three other technologies in a second site

What communications are required between the two sites if the customer wants to install a Cortex XSOAR engine in the second site?

- a. The Cortex XSOAR server at the first site must be able to initiate a connection to the Cortex XSOAR engine at the second site
- b. All connectivity is initiated from the Cortex XSOAR server on the first site via a managed cloud proxy
- c. Dedicated site-to-site virtual private network (VPN) is required for the Cortex XSOAR server at the first site to initiate a connection to the Cortex XSOAR engine at the second site
- d. The Cortex XSOAR engine at the first site must be able to initiate a connection to the
Cortex XSOAR server at the second site

#### 10

A customer agrees to do a 30-day proof of concept (POC) and wants to integrate with a product with which Cortex XSOAR is not currently integrated.

What is the appropriate response to the customer?

- a. Extend the POC window to allow the solution architects to build it
- b. Explain that custom integrations are not included in the POC
- c. Explain that it can be built by Professional Services, but it will take an additional 30 days
- d. Agree to build the integration as part of the POC

```text
选项b是合适的回应，因为通常来说，POC旨在演示现有的产品功能和集成，而不包括在POC期间定制的集成。以下是一些解释：
POC的目的: POC的主要目的是展示产品的核心功能和现有集成的性能，以帮助客户了解产品是否符合其需求和期望。通常，POC的时间有限，重点是演示产品的优势和价值。
定制集成的复杂性: 定制集成可能需要更多的时间和工作，因为它们需要开发、测试和部署新的集成，以适应客户的特定需求。在POC期间通常不会进行这种类型的工作，因为它会延长POC的时间和成本，并且可能会超出POC的范围。
明确的期望: 与客户建立明确的期望很重要。通过解释定制集成不包括在POC中，可以确保客户了解何时可以期望获得特定功能，并且可以评估是否需要额外的工作和资源来满足其需求。
因此，选项b是合适的回应，因为它有助于建立透明度，确保客户和供应商都了解POC的范围和目标。如果客户需要定制集成，可以在POC后讨论并计划相应的项目。
```

#### 13

Cortex XSOAR has extracted a malicious Internet Protocol (IP) address involved in command-and-control (C2) traffic.

What is the best method to block this IP from communicating with endpoints without requiring a configuration change on the firewall?

- a. Have XSOAR automatically add the IP address to a deny rule in the firewall
- b. Have XSOAR automatically add the IP address to a threat intelligence management
(TIM) malicious IP list to elevate priority of future alerts
- c. Have XSOAR automatically add the IP address to an external dynamic list (EDL) used
by the firewall
- d. Have XSOAR automatically create a NetOps ticket requesting a configuration change to the firewall to block the IP

```text
让我为每个选项进行详细解释和分析：
a. Have XSOAR automatically add the IP address to a deny rule in the firewall:
此选项建议XSOAR自动将恶意IP地址添加到防火墙的拒绝规则中。尽管这在理论上可能有效，但它需要对防火墙的配置进行直接更改，这可能需要较长的时间，而且可能需要特定的权限。此外，如果频繁添加规则，防火墙配置可能变得复杂且难以管理。
b. Have XSOAR automatically add the IP address to a threat intelligence management (TIM) malicious IP list to elevate priority of future alerts:
此选项建议将恶意IP地址添加到威胁情报管理（TIM）的恶意IP列表中，以提高未来警报的优先级。这种方法通常不会直接阻止流量，但它可以用于改进未来的安全警报，使其更容易识别类似的威胁。
c. Have XSOAR automatically add the IP address to an external dynamic list (EDL) used by the firewall:
这是最佳答案。此选项建议将恶意IP地址添加到由防火墙使用的外部动态列表（EDL）中。这将允许防火墙实时地检测和阻止与该IP地址相关的流量，而无需直接更改防火墙规则。这是一种有效且高效的方法，可以立即阻止与该IP地址相关的威胁。
d. Have XSOAR automatically create a NetOps ticket requesting a configuration change to the firewall to block the IP:
此选项建议XSOAR自动创建一个网络运维（NetOps）工单，请求对防火墙进行配置更改以阻止该IP。虽然这可以实现目标，但它涉及人工干预，可能需要时间来执行，并且可能不如实时阻止流量的方法那么快速和有效。
综上所述，选项c是最佳选择，因为它允许XSOAR将恶意IP地址添加到外部动态列表（EDL），以便防火墙可以实时地阻止与该IP地址相关的流量，而无需直接更改防火墙规则。这是一种高效的方法，可以快速应对威胁。
```

#### 17

How do sub-playbooks affect the incident Context Data?

- a. When set to global, sub-playbook tasks do not have access to the root context
- b. When set to private, task outputs do not automatically get written to the root context
- c. When set to global, parallel task execution is allowed
- d. When set to private, task outputs are automatically written to the root context

#### 22

Which statement applies to a Cortex XSOAR engine that is part of a load-balancing group?

- a. It does not appear in the engine drop-down menu when configuring an integration
instance
- b. It must be in a load-balancing group with at least three additional members
- c. It can be used separately as an engine only if directly connected to the XSOAR server
- d. It must have port 443 open to allow the XSOAR server to establish a connection

#### 24

Which integration allows data to be pushed from Cortex XSOAR into Splunk?

- a. SplunkUpdate integration
- b. Demisto App for Splunk integration
- c. SplunkPY integration
- d. ArcSight ESM integration

#### 28 X

Which task setting allows context output to a specific key?

- a. Extend context
- b. Task output
- c. Stop on errors
- d. tags

#### 30

What are two capabilities of a War Room? (Choose two)

- a. Run ad-hoc automation commands
- b. Create widgets for an investigation
- c. Act as an audit trail for an investigation
- d. Create playbooks for orchestration

#### 31

Which two Cortex XSOAR incident type features can be customized under Settings > Advanced > Incident Types? (Choose two)

- a. Setting reminders for an incident service level agreement (SLA)
- b. Defining whether a playbook runs automatically when an incident type is encountered
- c. Adding new fields to an incident type
- d. Dropping new incidents of the same type that contain similar information

#### 35 X

Which action allows Cortex XSOAR to access Docker in an air-gapped environment where the Docker page was manually installed after the Cortex XSOAR installation?

- a. Enable the Docker service
- b. Disable the Cortex XSOAR service
- c. Create a “docker” group and add the “Cortex XSOAR” or “demisto” user to this group
- d. Create a “Cortex XSOAR” or “demisto” group and add the “docker” user to this group

```text
c. 创建一个“docker”组，并将“Cortex XSOAR”或“demisto”用户添加到这个组中
这个选项意味着我们在操作系统中创建一个名为"docker"的用户组，然后将运行Cortex XSOAR的用户（可能是"Cortex XSOAR"或"demisto"）添加到这个组中。在大多数Linux系统中，安装Docker时通常会自动创建一个名为"docker"的组。该组的成员具有与Docker daemon互动的权限。因此，将Cortex XSOAR或demisto用户添加到这个组意味着我们正在授予这个用户与Docker daemon互动的权限。

d. 创建一个“Cortex XSOAR”或“demisto”组，并将“docker”用户添加到这个组中
这个选项建议我们创建一个以Cortex XSOAR或demisto命名的用户组，然后将docker用户添加到这个新创建的组中。这在逻辑上是没有意义的，因为Docker daemon通常作为root用户运行，并不需要被添加到任何特定的用户组中。此外，这种方式并不提供Cortex XSOAR访问Docker的权限。

简而言之，c和d的主要区别在于我们为哪个用户和哪个组授予访问权限。正确的做法是确保运行Cortex XSOAR的用户能够访问Docker，而这可以通过将其添加到"docker"组来实现。这就是为什么选项c是正确的。
```

#### 36 X

What does the Cortex XSOAR “Saved by Dbot” widget calculate?

- a. Amount saved in Dollars by using Cortex XSOAR instead of other products
- b. Amount of time saved by each playbook task within an incident
- c. Amount of time saved by Dbot’s machine learning (ML) capabilities
- d. Amount saved in Dollars according to actions carried out by all users in Cortex XSOAR across all incidents

#### 37 X

On a multi-tenanted v6.2 Cortex XSOAR server, which path leads to the server log for “Tenant1”?

- a. /var/lib/demisto/acc_Tenant1/server.log
- b. /var/log/demisto/Tenant1/server.log
- c. /var/log/demisto/acc_Tenant1/server.log
- d. /var/lib/demisto/server.log

#### 38

What is a benefit offered by Cortex XSOAR?

- a. It enables an end-to-end view of everything in the customer environment that affects digital employee productivity
- b. It provides holistic protection across hosts and containers throughout the application lifecycle
- c. It has the ability to customize the extensible platform to scale to business needs
- d. It allows the consolidation of multiple point products into a single integrated service

#### 39

Why is reputation scoring important in the Threat Intelligence Module of Cortex XSOAR?

- a. It helps identify threat intelligence vendors with substandard content
- b. It provides a mathematical model for combining scores from multiple vendors
- c. It allows for easy comparison between open-source intelligence and paid services
- d. It deconflicts prioritization when two vendors give different scores for the same indicator

#### 42 X

Which two playbook functionalities allow looping through a group of tasks during playbook execution? (Choose two)

- a. Sub-playbooks
- b. Playbook functions
- c. CommonPolling Playbooks
- d. Playbook tasks

```text
a. Sub-playbooks（子playbooks）
子playbooks可以理解为一个主playbook中引用的另一个playbook。它允许主playbook将特定的任务或一组任务委托给一个外部playbook。虽然子playbooks本身并不直接提供循环功能，但如果在子playbook中设置了循环，那么在主playbook中调用它时，这些循环也会被执行。

b. Playbook functions（playbook功能）
一般来说，playbook功能指的是playbook可以执行的内置或自定义功能。这些功能可能包括数据转换、计算或与外部系统的交互等。但它们通常不直接提供循环功能。

c. CommonPolling Playbooks（常见轮询Playbooks）
这是一种特殊类型的playbook，设计用于重复检查（轮询）某个条件，直到达到某个状态或超时。它特意为反复执行某个任务而设计，直到达到期望的结果或经过指定的时间。

d. Playbook tasks（playbook任务）
这是playbook中的单个步骤或活动。虽然单个任务本身不固有地循环，但可以通过特定的条件和配置设置它们进行重复，直到满足特定条件。

根据上述分析，能够支持在playbook执行期间循环任务的功能是：CommonPolling Playbooks和Playbook tasks。
```

#### 44 X

Which playbook feature allows concurrent execution of tasks?

- a. Automation tasks
- b. Parallel tasks
- c. Manual tasks
- d. Conditional tasks

#### 48

Which two manual actions are allowed on War Room entries? (Choose two)

- a. Mark as scheduled entry
- b. Mark as note
- c. Mark as artifact
- d. Mark as evidence

#### 51

Which playbook functionality allows grouping of tasks to create functional building blocks?

- a. Sub-playbook
- b. Playbook features
- c. Manual tasks
- d. Conditional tasks

#### 53

Which product enables the discovery, exchange, and contribution of security automation playbooks, built into Cortex XSOAR?

- a. XSOAR Marketplace
- b. XSOAR Threat Intelligence Platform (TIP)
- c. XSOAR Automated Systems
- d. XSOAR Ticketing Systems

#### 54

A Cortex XSOAR customer wants to send a survey to users asking them to input their manager’s email for a training use case so the manager can receive status reports on the employee’s training. However, the customer is concerned users will provide incorrect information to avoid sending status updates to their manager.

How can Cortex XSOAR most efficiently sanitize user input prior to using the responses in the playbook?

- a. Create a task that sends the survey responses to the analyst via email. If the responses are incorrect, the analyst fills out the correct response in the survey
- b. Create a task that sends the survey responses to the analyst via email. If the responses are incorrect, the analyst fills out the correct response in the survey
- c. Create a sub-playbook and import a list of manager emails into XSOAR. Use a conditional task comparison to check if the response matches an email on the list. If no matches are found, loop the sub-playbook and send the survey back to the user until a match is found
- d. Create a conditional task comparison to check if the response contains a valid email address

#### 57

What is used to display only file entries in a War Room?

- a. ;files from War Room CLI
- b. !files from War Room CLI
- c. Files and attachments filters
- d. Incident files section in layout builder

### Others

#### 11

Which service helps uncover attackers wherever they hide by combining world-class threat hunters with Cortex XDR technology that runs on integrated endpoint, network, and cloud data sources?

- a. Cloud Identity Engine (CIE)
- b. Threat Intelligence Platform (TIP)
- c. Virtual desktop infrastructure (VDI)
- d. Managed Threat Hunting (MTH)

```text
Managed Threat Hunting (MTH):
MTH 是一项服务，它涉及专业的威胁猎手团队，他们使用先进的安全工具和技术来主动搜索、检测和应对潜在的安全威胁。
这项服务的目标是发现威胁行为和攻击者的迹象，帮助组织及早识别和应对威胁。
MTH 通常依赖于实时监测和分析网络和系统活动，以及针对威胁的专业知识。
Threat Intelligence Platform (TIP):
TIP 是一种工具或平台，用于收集、管理、分析和分享威胁情报信息。
TIP 不一定涉及主动威胁猎手活动，而是更关注于整合和分析威胁情报，以帮助安全团队做出更明智的决策。
TIP 可以用于提供上下文和信息，以改进安全事件响应和决策制定。
总之，Managed Threat Hunting (MTH) 是一项服务，侧重于主动的威胁检测和响应，而Threat Intelligence Platform (TIP) 是一个工具或平台，用于管理和分析威胁情报数据，以支持安全运营和决策制定。它们在目的和实施上有明显区别。
```

#### 14 X

What is the size of the free Cortex Data Lake instance provided to a customer who has activated a TMS tenant, but has not purchased a Cortex Data Lake instance?

- a. 10TB
- b. 1TB
- c. 100 GB
- d. 10GB

#### 20

Which attack method is a result of techniques designed to gain access through vulnerabilities in the code of an operating system (OS) or application?

- a. Malware
- b. Exploit
- c. Ransomware
- d. phishing

#### 21

What is a benefit of user entity behavior analytics (UEBA) over security information and event management (SIEM)?

- a. UEBA can add trusted signers of Windows or Mac processes to a whitelist in the Endpoint Security Manager (ESM) Console
- b. UEBA establishes a secure connection in which endpoints can be routed, and it collects and forwards logs and files for analysis
- c. SIEMs have difficulty detecting unknown or advanced security threats that do not involve
malware, such as credential theft
- d. SIEMs supports only agentless scanning, not agent-based workload protection across VMs, containers, Kubernetes.

#### 23 X

Which step is required to prepare the virtual desktop infrastructure (VDI) golden image?

- a. Run the VDI conversion tool
- b. Ensure the latest content updates are installed
- c. Set the memory dumps to manual setting
- d. Review any portable executable (PE) files WildFire determined to be malicious

```text
这个问题问的是关于准备虚拟桌面基础设施（VDI）黄金镜像的步骤，每个选项的详细解释如下：
a. Run the VDI conversion tool (运行VDI转换工具)：
这个选项提到了运行VDI转换工具，但它没有提供足够的上下文来理解这一步骤的目的或必要性。通常情况下，VDI转换工具用于将虚拟机镜像转换为适用于VDI环境的格式。但问题没有明确说明此步骤是否必需，因此不能确定它是否正确。
b. Ensure the latest content updates are installed (确保安装了最新的内容更新)：
这是正确答案。在准备VDI黄金镜像时，确保安装了最新的内容更新非常重要。这包括最新的安全补丁、签名和威胁情报，以确保镜像具备最新的安全性和防护能力。
c. Set the memory dumps to manual setting (将内存转储设置为手动设置)：
这个选项提到了将内存转储设置为手动设置，但它没有提供足够的上下文来理解这一步骤的目的或必要性。内存转储通常用于分析系统故障，而不是为了准备VDI黄金镜像。
d. Review any portable executable (PE) files WildFire determined to be malicious (审查WildFire确定为恶意的任何可执行（PE）文件)：
这个选项提到了审查WildFire确定为恶意的可执行文件，这是一项安全性措施，但它不是准备VDI黄金镜像的步骤。这个步骤通常与安全事件响应和恶意软件分析相关，而不是与VDI镜像的准备相关。
综上所述，正确答案是选项b，即确保安装了最新的内容更新，以确保VDI黄金镜像具备最新的安全性和防护能力。其他选项要么没有提供足够的上下文，要么与VDI镜像准备不相关。
```

#### 40

Which solution profiles network behavior metadata, not playloads and files, allowing effective operation regardless of encrypted or unencrypted communication protocols, like HTTPS?

- a. Endpoint detection and response (EDR)
- b. Security Information and Event Management (SIEM)
- c. Endpoint protection platform (EPP)
- d. Network Detection and Response (NDR)

#### 41

Which method is used for third-party network data consumption?

- a. File reader to the /var/log/messagers file on the device
- b. Open Database Connectivity (OOBC) connection to network device database
- c. Common Event Format (CEF) via broker Syslog module
- d. Scripts library from the action center

#### 50

Which command-line interface (CLI) query would retrieve the last three Splunk events?

- a. !query using=splunk_instance_1 query=”* | last 3”
- b. !search using=splunk_instance_1 query=”* | head 3”
- c. !search using=splunk_instance_1 query=”* | last 3”
- d. !search using=splunk_instance_1 query=”* | 3”

## 考前忠告

1. 太绝对的词大概率错误的，例如**must/only**
