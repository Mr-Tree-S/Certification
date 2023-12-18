# PCDRA

## Study Approach

1. Read PCDRA Study Guide
2. Check RUSH
3. Refer
   > <https://www.examtopics.com/exams/palo-alto-networks/pcdra/view/>

---

## **PCDRA Study Guide**

## **RUSH**

### XDR

#### 3 X

Which built-in dashboard would be the best option for an executive, if they were looking for the Mean Time to Resolution (MTTR) metric?

- A. Security Manager Dashboard
- B. Data Ingestion Dashboard
- C. Security Admin Dashboard
- D. Incident Management Dashboard

```不多说了，选C，打开这个dashboard，在右上角```

#### 10 X

When viewing the incident directly, what is the “assigned to” field value of a new Incident that was just reported to Cortex?

- A. Pending
- B. It is blank
- C. Unassigned
- D. New

```不多说了，XDR上看过，是Unassigned```

#### 12 X

Where would you view the WildFire report in an incident?

- A. next to relevant Key Artifacts in the incidents details page
- B. under Response --> Action Center
- C. under the gear icon --> Agent Audit Logs
- D. on the HUB page at apps.paloaltonetworks.com

```Answer should be - A.```

#### 13 X

```Answer should be - A. The blue color codes for low severity incidents.```

#### 15 ？

Which type of BIOC rule is currently available in Cortex XDR?

- A. Threat Actor
- B. Discovery
- C. Network
- D. Dropper

```XDR上Discovery和Dropper都有，可能一个是后来新出的type，答案推荐D，那就选D吧```

#### 19 X

What is the purpose of targeting software vendors in a supply-chain attack?

- A. to take advantage of a trusted software delivery method.
- B. to steal users’ login credentials.
- C. to access source code.
- D. to report Zero-day vulnerabilities.

```text
针对软件供应商的供应链攻击的目的是：

- A. 利用可信软件交付方法。
供应链攻击的关键在于攻击者通过渗透可信的软件供应商来分发恶意软件或执行其他恶意活动。因为用户通常信任这些供应商提供的软件更新和补丁，所以这种攻击方式能够有效地利用这种信任来传播恶意代码。
- B. 窃取用户的登录凭证。
尽管窃取用户凭证可能是某些网络攻击的目标，但这并不是针对软件供应商的供应链攻击的主要目的。
- C. 访问源代码。
访问源代码可能是攻击者的目标之一，但在供应链攻击中，这通常是手段而不是最终目的。攻击者可能会修改源代码来植入恶意软件，但这只是为了更广泛地分发恶意代码。
- D. 报告零日漏洞。
报告零日漏洞通常是安全研究人员或白帽黑客的工作，而不是网络攻击者的目的。供应链攻击者通常利用漏洞而不是报告它们。

因此，最准确的答案是 - A. 利用可信软件交付方法。 这是供应链攻击常见的目的，通过这种方法，攻击者能够在广大用户中有效地传播恶意软件或进行其他恶意活动。
```

#### 30 X

If you have an isolated network that is prevented from connecting to the Cortex Data Lake, which type of Broker VM setup can you use to facilitate the communication?

- A. Broker VM Pathfinder
- B. Local Agent Proxy
- C. Local Agent Installer and Content Caching
- D. Broker VM Syslog Collector

```text
I believe the answer is B.
Here is the admin guide, see the second bullet: https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-
Guide/Activate-the-Local-Agent-Settings
Caching just means it will cache the data, but if it doesn't have the data it will try to go get it. This won't work in an isolated network so C isn't
correct.
```

#### 36 X

Which statement is true for Application Exploits and Kernel Exploits?

- A. The ultimate goal of any exploit is to reach the application.
- B. Kernel exploits are easier to prevent then application exploits.
- C. The ultimate goal of any exploit is to reach the kernel.
- D. Application exploits leverage kernel vulnerability.

```text
在理解应用程序漏洞（Application Exploits）和内核漏洞（Kernel Exploits）时，有几个关键概念需要明确。这些概念有助于区分这两种类型的漏洞以及它们的目标和影响。让我们来分析您给出的选项：

- A. 任何漏洞的最终目标都是到达应用程序。
这个说法过于笼统。应用程序漏洞的目标可能是应用程序本身，但内核漏洞的目标是操作系统的核心部分。
- B. 内核漏洞比应用程序漏洞更容易防止。
通常情况下，内核漏洞更难以预防和检测，因为它们涉及到操作系统的核心部分，这些部分通常不容易接触或监控。
- C. 任何漏洞的最终目标都是到达内核。
对于很多高级的攻击者来说，达到内核级别的控制确实是一个主要目标，因为这样可以获得对整个系统的完全控制。
- D. 应用程序漏洞利用内核漏洞。
应用程序漏洞和内核漏洞是不同的。应用程序漏洞一般是指在特定应用程序中的安全漏洞，而不一定涉及或利用内核漏洞。

考虑到这些信息，最准确的陈述是 - C. 任何漏洞的最终目标都是到达内核。达到内核级别的控制可以给攻击者提供对整个系统的广泛控制，这对于攻击者来说是非常有价值的。因此，虽然不是所有攻击的最终目标都是内核，但从战略角度来看，内核级别的访问权确实是许多复杂攻击的主要目标。
```

#### 38 X

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

#### 39 X

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

#### 40 X

Which of the following protection modules is checked first in the Cortex XDR Windows agent malware protection flow?

- A. Hash Verdict Determination
- B. Behavioral Threat Protection
- C. Restriction Policy
- D. Child Process Protection

```text
Correct Answer - D. Child Process Protection
https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Prevent-Administrator-Guide/File-Analysis-and-Protection-Flow
If the process tries to launch any child processes, the Cortex XDR agent first evaluates the child process protection policy. If the parent process is a known targeted process that attempts to launch a restricted child process, the Cortex XDR agent blocks the child processes from running and reports the security event to Cortex XDR.
```

#### 50 X

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

#### 55 X

Which statement regarding scripts in Cortex XDR is true?

- A. Any version of Python script can be run.
- B. The level of risk is assigned to the script upon import.
- C. Any script can be imported including Visual Basic (VB) scripts.
- D. The script is run on the machine uploading the script to ensure that it is operational.

```text
I think - B. A is wrong for sure, you need at least Python 3.7 to run scripts on your endpoint directly.
https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Run-Scripts-on-an-Endpoint
```

#### 57 X

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

#### 60 X

Which of the following paths will successfully activate Remediation Suggestions?

- A. Alerts Table > Right-click on a process node > Remediation Suggestions
- B. Incident View > Actions > Remediation Suggestions
- C. Causality View > Actions > Remediation Suggestions
- D. Alerts Table > Right-click on an alert > Remediation Suggestions

```text
This should be - B. Incidents > click the 3 dots > Remediation Suggestions
C is wrong because Actions > Live Terminal
```

#### 65 X

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

#### 70 X

Which Exploit Protection Module (EPM) can be used to prevent attacks based on OS function?

- A. Memory Limit Heap Spray Check
- B. DLL Security
- C. UASLR
- D. JIT Mitigation

```text
在防御基于操作系统功能的攻击时，Exploit Protection Module (EPM) 提供了多种机制。每个模块都针对特定类型的攻击或漏洞提供保护。根据您提供的选项，我们来分析哪种 EPM 可以用来预防基于操作系统功能的攻击：

- A. Memory Limit Heap Spray Check
堆喷射（Heap Spray）是一种常见的攻击技术，攻击者试图在目标程序的堆内存中填充大量的数据。此选项可能涉及防止此类攻击，但它并不直接与操作系统功能本身相关。
- B. DLL Security
DLL 安全性与动态链接库（DLL）文件有关。虽然 DLL 是操作系统的一个重要组成部分，但 DLL 安全性通常指的是确保 DLL 文件的完整性和安全性，而不是直接针对基于操作系统功能的攻击。
- C. UASLR (User Address Space Layout Randomization)
地址空间布局随机化是一种安全技术，用于随机排列内存地址的位置，使得攻击者难以预测和利用内存中特定区域的数据。这是一种基于操作系统功能的防御机制，可以有效防止多种内存相关的攻击。
- D. JIT Mitigation
即时编译（JIT）缓解通常与浏览器和某些应用程序中的 JIT 编译器有关。它旨在防止利用 JIT 编译过程中的漏洞，而不是直接针对操作系统功能的攻击。

在这些选项中，- C. UASLR (User Address Space Layout Randomization) 最直接地与操作系统功能相关，并提供了基于这些功能的攻击防御。UASLR 通过增加内存布局的不确定性来提高操作系统的安全性，从而阻止基于内存的攻击。
```

#### 77 X

Which version of python is used in live terminal?

- A. Python 3 with specific XDR Python libraries developed by Palo Alto Networks
- B. Python 3 with standard Python libraries
- C. Python 2 and 3 with standard Python libraries
- D. Python 2 and 3 with specific XDR Python libraries developed by Palo Alto Networks

```text
The Answer is - B.
https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Initiate-a-Live-Terminal-Session#:~:text=The%20Python%20command%20interpreter%20uses%20Unix%20command%20syntax%20and%20supports%20Python%203%20with%20standard%20Python%20libraries
```

## 考前忠告

1. 太绝对的词大概率错误的，例如**must/only**
2. 选跟题干关键词相关度较高的
