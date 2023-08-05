# CISSP Tips

## 复习思路

1. 根据本章小结、考试要点阅读章节内容，然后书面实验、复习题
2. 对应域的练习题来一遍，对应错题再回归书本
3. 边执行上面两步边总结文档
4. 所有域全部过完，模拟题全部过一遍，然后根据自己时间做**开源题**
    - <https://www.briefmenow.org/isc2/>
    - <https://www.exam-answer.com/isc>
    - <https://www.examtopics.com/exams/isc/cissp/>
    - <https://vceguide.com/isc-certification/>

---

## **Domain 1: Security and Risk Management (1/2/3/4)**

### Chapter 1 Security Governance Through Principles and Policies

- ISO/IEC
  - 27001 信息安全管理体系的要求
  - 27002 专注于信息安全控制实践的国际标准
  - 27003 信息安全管理体系实施指南
  - 27005 信息安全风险管理
- STRIDE 微软开发的威胁分类方案
  - 欺骗(Spoofing)
  - 篡改(Tampering)
  - 否认(Repudiation)
  - 信息泄露(Information Disclosure)
  - 拒绝服务(DOS)
  - 特权提升(Elevation of Privilege)
- 运维是安全手下的打工仔，所有的汇报或者高级职位相关的事情，都与 IT 运维部门无关
- Due diligence: 尽职调查，不如说是尽职搜索，尽职收集信息，然后考虑，评估，这是在做事前的准备和研究
- Due care: 尽职关心，就是实际做事，采取行动，以及后续的维护

### Chapter 2 Personnel Security and Risk Management Concepts

- 控制分类
  - 管理性控制
  - 技术性（逻辑性）控制
  - 物理性控制

### Chapter 3 Business Continuity Planning

- MTD: maximum tolerable downtime
- AV: asset value
- EF: exposure factor
- SLE: single loss expectancy
- ARO: annualized rate of occurrence
- ALE: annualized loss expectancy
- 业务影连续性计划
  - 项目范围和计划
    - 业务组织分析
    - 选择 BCP 团队
    - 资源需求
    - 法律法规要求
  - BIA
    - 确定业务优先级：什么业务是最关键和重要的
    - 风险识别
    - 可能性评估
    - 影响评估
    - 资源优先级排序：什么风险应该最先考虑给资源
  - CP
    - 策略开发：BIA 和 CP 间的桥梁
    - 预备和处理：设计具体的过程和机制
  - 计划批准和实施
    - 计划批准
    - 计划实施
    - 培训和教育
    - BCP 文档化
- 测试和演练
  - 确保计划有效
  - 确保人员培训

### Chapter 4 Laws, Regulations, and Compliance

- 国际针对计算机犯罪难处理
  - 主要是法律问题，甚至在美国各州的法律都不完全相同，很可能在处理计算机犯罪的时候触犯别的州法律以及宪法
- GDPR
  - 遗忘权，允许人们要求公司删除不再需要的个人信息

---

## **Domain 2: Asset Security 5**

### Chapter 5 Protecting Security of Assets

- 保护隐私数据，对数据的处理方式(CN.126 EN.342)
  - 假名：其实就是别名，并不能真正保护数据隐私
  - 匿名：masking 如果真的匿名化，就不必再遵守 GDPR
- 这几个名词读汉语很容易忘记他们的区别和严重程度的区别
  - 擦除(Erasing)/清理(Clearing) 这俩完全等于点鼠标删除，和格式化移动下指针，根本不属于安全的处理方式
  - 清除，根除(Purging)这才是真正安全的处理名词
    - 消磁
    - 物理粉碎
    - 化学腐蚀

---

## **Domain 3: Security Architecture and Engineering (6/7/8/9/10)**

### Chapter 6 Cryptography and Symmetric Key Algorithms

- Diffie-Hellman 最实用的密钥分发交换
- Cryptanalysis is used to breach cryptographic security systems and gain access to the contents of encrypted messages

### Chapter 7 PKI and Cryptographic Applications

- PKI:作为可信任的第三方，为不认识的双方提供可信通信;X.509
  - CA:可信发证机构
  - 证书:一个主体的公钥签注副本
  - OCSP:实时验证证书的渠道
  - RA:证书注册机构，做一下基础资料验证，然后发给 CA，CA 再决定发不发证书
- Digital Signatures
  - nonrepudiation
  - assure the recipient that the message was not altered while in transit between the sender and recipient
- 线路加密
  - 链路加密：所有数据都是被加密的，每个数据包在每个中继只有解密后重新加密，才能继续发给下一个中继点，速度慢
  - 端到端加密：不加密报头/尾/IP 地址/路由数据，速度快
- 公钥证书，是以数字方式签名的声明，它将公钥的值与持有相应私钥的主体身份绑定在一起
- TPM:主板上的一块芯片，保存和管理用于全硬盘加密的密钥，如果有人强拆硬盘，那么没有这个 TPM 里的密钥，你把硬盘装到新电脑里也无法解密
- 电子邮件
  - PGP:信任网，简言之就是拉个群，你想加入，必须有人信任你，同意你进，才行
  - S/MIME:通过 X.509 证书交换密码密钥，这些证书包含的公钥用于数字签名和交换对称密钥，RSA 用来加密公钥

### Chapter 8 Principles of Security Models, Design, and Capabilities

- 非干涉模型：不关注数据本身的流动，发生在较高安全级别的操作不会影响发生在较低安全级别的操作
- 状态机模型要求，如果一个组件发生故障，系统应该变到更安全的状态，比如 Windows 蓝屏后再开机进入安全模式
- TCB: trusted hardware, software and firmware
- Security kernel 安全内核实现了系统的主体和客体之间的授权访问关系
- CC 标准
  - PP:客户的安全需求
  - ST:供应商能提供的安全功能申明
  - 然后两个一比较，最接近匹配的就是最合适的，这里比较的就是 EAL 级别
- 认证(Certification)/认可(Accrediation)
  - 认证：分析系统组件能否满足所期望的安全目标，然后进行评级
  - 认可：管理层接受风险，系统可以上线

### Chapter 9 Security Vulnerabilities, Threats, and Countermeasures

- two types of covert channels: storage and timing

### Chapter 10 Physical Security Requirements

- 服务器机房不宜人员常驻，更具效率和安全的机房可以不考虑必须与人相容
- 最常见的边界安全技术，竟然是照明，我还以为是围栏

---

## **Domain 4: Communication and Network Security (11/12)**

### Chapter 11 Secure Network Architecture and Securing Network Components

这一章的章节的小结，明显和 13 相比少很多，确实在整章浏览的时候，感觉也没啥印象太深刻的东西

- OSI 模型
  - 上层：信息(message),数据(data)；网关
  - 传输层：TCP 段(segment)/UDP 数据报(datagram)
  - 网络层：包(packet)；路由器
  - 链路层：帧(frame)；网桥，交换机
  - 物理层：比特(bit)；中继器
- IPv4 32 位/IPv6 128 位
- 邪恶双胞胎(相同的 SSID)，属于中间人攻击
- 无线安全协议
  - WEP:RC4,初始向量一下就被破解，不安全
  - WPA:为了替代 WEP 的临时协议，是为了后面完整的 802.11i 做铺垫
  - WPA2:AES 加密；个人模式/企业模式；能兼容 WPA, WEP
  - EAP:802.1X 无线身份验证协议(服务器验证用户)，方便集成其他技术解决方案
  - PEAP:EAP 最初设计用于物理隔离通道，所以不加密，PEAP 通过 TLS 解决了加密的问题

### Chapter 12 Secure Communications and Network Attacks

- 链路加密：所有消息在被传输之前进行加密，在每一个节点，先对收到的消息解密，然后再使用下一个节点的密钥加密，再传输；所以，每个节点都要加解密，密钥非常多，任何其中一个节点被攻破，直接 G
- VPN
  - PPTP:微软点对点加密(MPPE)
  - L2TP:源自 PPTP 和 L2F 的结合，使用 IPsec 作为安全机制
  - IPsec:传输模式/隧道模式；AH, ESP
- 身份认证协议
  - PAP:明文发送用户名和密码；二次握手；客户端可无限暴破
  - CHAP:3 次握手；hash 验证；挑战应答机制抗重放攻击
- SSL/TLS
  - SSL 使用对称加密传输数据，非对称加密或公钥加密实现对等认证；主要用途是为客户端验证服务器，比如 https 有那个绿色小锁，你就觉得这个站安全
  - HTTPS 替换 HTTP,防止无连接状态 Web 会话轻松被劫持；这里的 S 一开始就是指 SSL,后来 TLS 是 SSL 升级版，替换了它，所以现在指 TLS
  - TLS 是一个两层接口安全协议：TLS 记录协议(Record Protocol)/TLS 握手协议(Handshake Protocol)
- Callback systems 回拨系统
- Smurf:将回复地址设置为受害者 IP，然后广播，然后大家收到广播后，一起给受害者 IP 发包

---

## **Domain 5: Identity and Access Management (13/14)**

### Chapter 13 Managing Identity and Authentication

- 访问控制步骤
  - 标识(Identification)
  - 验证(Authentication)
  - 授权(Authorization)
  - 审计(Accountability):审计是看的行为，属于检测型访问控制类型
- 视网膜/虹膜
  - 视网膜：眼球后方的血管图案，既然是眼球后面的血管，就要设备很近，发射红光才能看到，所以体验很不好
  - 虹膜：瞳孔周围一圈彩色部分
- 智能卡：美国政府人员使用(CAC, Common Access Card)/(PIV, Personal Identity Verification)
- FAR(false acceptance rate); FRR(false rejection rare); CER(crossover error rate)/EER(equal error rate)
- Kerberos (麻省理工)
  - **因为是对称加密，所以任何跟公钥私钥有关的，都无关**
  - 主要目的：身份验证，而 AES 部分也提供完整性和机密性，但是不保证完整性，也没有日志供审计
  - 主要组件：密钥分发中心(KDC)，KDC 里有两个服务组件(AS:Authentication Service/TGS:Ticket Granting Service)
  - 秘密密钥：在 KDC 和委托人之间共享，KDC 存储
  - 会话密钥：两个委托人之间共享，会话结束销毁
  - 弱点：KDC 出问题就导致单点故障；秘密密钥临时存储在用户端，mimikatz 偷票据的原理
- SESAME(欧洲众厂商的安全系统)，目的是扩展 kerberos 和弥补它的缺陷，不只有对称还加了个非对称呗，就弥补了？哈哈
- AAA
  - RADIUS:网络访问服务器是 RADIUS 身份验证服务器的客户端
  - Diameter:是 RADIUS 的升级版，但是不向后兼容；有趣的是 RADIUS（Remote Authentication Dial-in User Service）这个首字母大学组合刚好是半径 r,所以它的升级版就是直径 d
  - TACACS:只支持静态口令
  - TACACS+:是 RADIUS 的替代方案，也是现代最常用的，毕竟最新出的集大成者，TCP 连接，动态密码
- Managing the Identity and Access Provisioning Lifecycle
  - Provisioning
  - Account Review
  - Account Revocation

### Chapter 14 Controlling and Monitoring Access

- 访问控制模型
  - DAC
  - NDAC
    - RBAC
    - R-BAC
    - ABAC
    - MAC 基于 BLP,主客体都有安全标签(Security Label),标签中就包含安全许可(security clearance)/安全分级(security classification)
- Constrained user interfaces 约束的用户界面：限制用户选择功能的界面
- Database views 数据视图：限制用户访问数据库中的数据，你只能看到这个图里展示的，你不能直接查

---

## **Domain 6: Security Assessment and Testing 15**

### Chapter 15 Security Assessment and Testing

- PCI DSS 要求至少每年做一次扫描，且应用变更后重新扫描
- 管理评审，先做审计，然后把审计报告和上次管理评审的遗留问题，一起作为输入，放到这次管理评审讨论，然后高级管理层会决定接受，拒绝，还是再收集信息重新规划组织评审
- Synthetic transactions is a way to test the behavior and performance of critical services
- fuzzing 跟你理解的 web fuzz 不是一个概念，这里指自动化随机生成大量无效或随机输入，试图导致崩溃，错误，内存泄露等
- phsihing not fishing 不会真的出这么搞笑的题吧
- User acceptance testing 不是真的拿给用户去测，而是我们自己测试的最后阶段，验证开发的东西是否满足用户的需求
- edit controls 当作 code review 即可，是一种预防性控制
- 渗透测试不会提供 a method to correct the security flaws

---

## **Domain 7: Security Operations (16/17/18/19)**

### Chapter 16 Managing Security Operations

- 配置管理和变更管理很接近

### Chapter 17 Preventing and Responding to Incidents

- NIDS: 对现有网络影响不大，对主机性能也无影响
- 基于知识/特征/签名的 IDS（容易漏报）；基于行为/触发式规则/统计分析的 IDS（容易误报）

### Chapter 18 Disater Recovery Planning

- 故障防护/应急开放
- 数据库恢复
  - 远程镜像：不是单单的数据，而是实时同步运行的两个数据库系统或软件，非常精确，但是很贵
  - 电子链接：数据库备份批量传送，有相当长的备份时间延迟
  - 远程日志：传送的日志备份，不过时间更短

### Chapter 19 Investigations and Ethics

---

## **Domain 8: Software Development Security (20/21)**

### Chapter 20 Software Development Security

这我看都不用看，第一次遇到小结和要点一页纸写完的，肯定没啥东西鸭，但是做了课后题，哈哈哈，一上来就错了好几个，还是有很多知识点的嘛，不能因为你不喜欢，就抱着先入为主的态度，带有色眼镜看这章鸭，哈哈哈哈

- SQL 内键/外键，参照完整性，NOSQL 那些再重新梳理一下，思维导图
- 数据 表=relation 列=字段/属性 行=记录/元组
- RPC(request for change):每个变更都应该经过审查和批准，这些 RFC 可能会得到变更会员会(CAB:change advisory board)的批准。组织使用的安全信息和时间管理(SIME)以及安全编排自动化和响应(SOAR)平台通常不包含有关变更管理流程的信息
  - **说白了，就是安全管理中，不记录变更管理，这不是安全日志那种记录**
- SDLC
  - 瀑布：顺序开发，需求和设计以及文档编制上花大量时间，不需要迭代，只能回退一个阶段
  - 螺旋：封装了许多迭代的其他模型，又叫元模型
  - 敏捷：快速开发，快速迭代
- DevOps:Dev & Ops 相结合，一定是有两 part
- SDS:安全基础设施可以被 Dev 用代码操控
- PDCA
  - Plan - established
  - Do - implemented
  - Check - monitor and review
  - Act - maintain and improve

### Chapter 21 Malicious Code and Application Attacks

- 中英对照，学学专业名词还有点意思

---

## 考前忠告

1. 一定要仔细读题目的**最后几个字，把它圈出来**:
    - 问的是目标就只找答案跟目标有关；
    - 问的成本就是成本、不管效率什么的；
    - 问质量就找质量，不管什么知识产权隐私之类的；
2. 安全不关注性能，效率一类的词，甚至在 Web 安全中，可用性也处于三性中的最低地位
3. 答案的高优先级：
    - 人身安全
    - 最高管理层
    - 含有非常绝对词的选项
4. 成功/失败影响的关键/最主要因素，往往是最开始的部分，比如：
    - 明确范围、标签化
5. 越是技术问题，越要谨慎。毁灭人类的不是无知和弱小，而是傲慢
6. 还有如果这个题，明显送分题，那可能是读题出了问题，把相似但其实不同的词，理解成了一个意思；千万别觉得有送分题，只有你知道这个知识点，它才是送分题，不存在对任何人来说都是的送分题，谨慎！！！
7. 如果遇到不确定的题目，一定要重新读题，然后先筛选错误答案，最后留下两个选项二选一，不要四个选项看第一眼觉得有点熟悉，再看一眼又都觉得有点陌生，然后没过几秒就选了一个答案，经过我的测试，有这种心路历程的题目，几乎都是答错 : D
