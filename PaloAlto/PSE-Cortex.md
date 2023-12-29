# PSE-Cortex

## Refer

> <https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Overview>

---

## **RUSH**

### XDR

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

#### 29 X

Which two methods does the Cortex XDR agent use to identify malware during a scheduled scan? (Choose two)

- a. WildFire hash comparison
- b. Signature comparison
- c. Dynamic analysis
- d. Heuristic analysis

```text
a. WildFire hash comparison (WildFire哈希比较)：
这个选项指的是Cortex XDR代理会将文件的哈希值与Palo Alto Networks的WildFire数据库中已知的恶意文件哈希进行比较。如果发现匹配，那么该文件将被标记为恶意的。这种方法主要依赖于已知的威胁数据库。
b. Signature comparison (签名比较)：
签名比较是传统的恶意软件检测方法。恶意软件通常有特定的“签名”或模式，这些模式可以被捕获并存储在数据库中。通过将文件与这些已知的签名进行比较，可以确定文件是否恶意。这种方法高效地检测已知的恶意软件，但可能无法检测到新型或修改过的恶意软件。
c. Dynamic analysis (动态分析)：
动态分析通常涉及在受控环境（如沙盒）中运行并观察可疑文件的行为，以确定其是否恶意。这种方法可以用于识别新型或修改过的恶意软件，因为它不仅仅基于已知的签名。但在预定扫描中，Cortex XDR代理本身不会在终端上运行动态分析。
d. Heuristic analysis (启发式分析)：
启发式分析涉及到检查文件的特性和行为来识别以前未知的威胁或已知威胁的新变种。它不是基于固定的签名，而是基于文件的行为和其他特征来判断。这种方法可以帮助检测那些尚未被列入签名数据库的新型或变种恶意软件。
综上所述，Cortex XDR代理在进行预定扫描时最可能使用的两种方法是：a. WildFire哈希比较 和 b. 签名比较。
```

#### 47 X

Which type of log is ingested natively in Cortex XDR Pro per TB?

- a. Docker
- b. Microsoft Office 365
- c. Demisto
- d. Google Kubernetes Engine

### XSOAR

#### 9 X

A customer wants the main Cortex XSOAR server installed in one site and wants to integrate with three other technologies in a second site

What communications are required between the two sites if the customer wants to install a Cortex XSOAR engine in the second site?

- a. The Cortex XSOAR server at the first site must be able to initiate a connection to the Cortex XSOAR engine at the second site
- b. All connectivity is initiated from the Cortex XSOAR server on the first site via a managed cloud proxy
- c. Dedicated site-to-site virtual private network (VPN) is required for the Cortex XSOAR server at the first site to initiate a connection to the Cortex XSOAR engine at the second site
- d. The Cortex XSOAR engine at the first site must be able to initiate a connection to the
Cortex XSOAR server at the second site

#### 28 X

Which task setting allows context output to a specific key?

- a. Extend context
- b. Task output
- c. Stop on errors
- d. tags

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

#### 42 X

Which two playbook functionalities allow looping through a group of tasks during playbook execution? (Choose two)

- a. Sub-playbooks
- b. Playbook functions
- c. CommonPolling Playbooks
- d. Playbook tasks

## 考前忠告

1. 太绝对的词大概率错误的，例如**must/only**
2. 选跟题干**关键词**相关度高的
