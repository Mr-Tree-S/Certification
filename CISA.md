# CISSP Tips


## 复习思路
1. 章节课程过一遍，大概了解概念
2. 章节模拟过一遍，对照解析回顾错题，总结文档
3. 综合模拟过一遍，回顾错题，总结文档
---


## **Domain 1: Security and Risk Management (1/2/3/4)**
### Chapter 1 Security Governance Through Principles and Policies
- ISO/IEC
    - 27001 信息安全管理体系的要求
    - 27002 专注于信息安全控制实践的国际标准
    - 27003 信息安全管理体系实施指南
    - 27005 信息安全风险管理
- STRIDE  微软开发的威胁分类方案
    - 欺骗(Spoofing)
    - 篡改(Tampering)
    - 否认(Repudiation)
    - 信息泄露(Information Disclosure)
    - 拒绝服务(DOS)
    - 特权提升(Elevation of Privilege)
- 运维是安全手下的打工仔，所有的汇报或者高级职位相关的事情，都与IT运维部门无关
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
        - 选择BCP团队
        - 资源需求
        - 法律法规要求
    - BIA
        - 确定业务优先级：什么业务是最关键和重要的
        - 风险识别
        - 可能性评估
        - 影响评估
        - 资源优先级排序：什么风险应该最先考虑给资源
    - CP
        - 策略开发：BIA和CP间的桥梁
        - 预备和处理：设计具体的过程和机制
    - 计划批准和实施
        - 计划批准
        - 计划实施
        - 培训和教育
        - BCP文档化
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
  - 匿名：masking 如果真的匿名化，就不必再遵守GDPR
- 这几个名词读汉语很容易忘记他们的区别和严重程度的区别
    - 擦除(Erasing)/清理(Clearing)  这俩完全等于点鼠标删除，和格式化移动下指针，根本不属于安全的处理方式
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
    - RA:证书注册机构，做一下基础资料验证，然后发给CA，CA再决定发不发证书
- Digital Signatures
    - nonrepudiation
    - assure the recipient that the message was not altered while in transit between the sender and recipient
- 线路加密
    - 链路加密：所有数据都是被加密的，每个数据包在每个中继只有解密后重新加密，才能继续发给下一个中继点，速度慢
    - 端到端加密：不加密报头/尾/IP地址/路由数据，速度快
- 公钥证书，是以数字方式签名的声明，它将公钥的值与持有相应私钥的主体身份绑定在一起
- TPM:主板上的一块芯片，保存和管理用于全硬盘加密的密钥，如果有人强拆硬盘，那么没有这个TPM里的密钥，你把硬盘装到新电脑里也无法解密
- 电子邮件
    - PGP:信任网，简言之就是拉个群，你想加入，必须有人信任你，同意你进，才行
    - S/MIME:通过X.509证书交换密码密钥，这些证书包含的公钥用于数字签名和交换对称密钥，RSA用来加密公钥
### Chapter 8 Principles of Security Models, Design, and Capabilities
- 非干涉模型：不关注数据本身的流动，发生在较高安全级别的操作不会影响发生在较低安全级别的操作
- 状态机模型要求，如果一个组件发生故障，系统应该变到更安全的状态，比如Windows蓝屏后再开机进入安全模式
- TCB: trusted hardware, software and firmware
- Security kernel 安全内核实现了系统的主体和客体之间的授权访问关系
- CC标准
    - PP:客户的安全需求
    - ST:供应商能提供的安全功能申明
    - 然后两个一比较，最接近匹配的就是最合适的，这里比较的就是EAL级别
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
这一章的章节的小结，明显和13相比少很多，确实在整章浏览的时候，感觉也没啥印象太深刻的东西
- OSI模型
    - 上层：信息(message),数据(data)；网关
    - 传输层：TCP 段(segment)/UDP 数据报(datagram)
    - 网络层：包(packet)；路由器
    - 链路层：帧(frame)；网桥，交换机
    - 物理层：比特(bit)；中继器
- IPv4 32位/IPv6 128位
- 邪恶双胞胎(相同的SSID)，属于中间人攻击
- 无线安全协议
    - WEP:RC4,初始向量一下就被破解，不安全
    - WPA:为了替代WEP的临时协议，是为了后面完整的802.11i做铺垫
    - WPA2:AES加密；个人模式/企业模式；能兼容WPA, WEP
    - EAP:802.1X无线身份验证协议(服务器验证用户)，方便集成其他技术解决方案
    - PEAP:EAP最初设计用于物理隔离通道，所以不加密，PEAP通过TLS解决了加密的问题
### Chapter 12 Secure Communications and Network Attacks
- 链路加密：所有消息在被传输之前进行加密，在每一个节点，先对收到的消息解密，然后再使用下一个节点的密钥加密，再传输；所以，每个节点都要加解密，密钥非常多，任何其中一个节点被攻破，直接G
- VPN
    - PPTP:微软点对点加密(MPPE)
    - L2TP:源自PPTP和L2F的结合，使用IPsec作为安全机制
    - IPsec:传输模式/隧道模式；AH, ESP
- 身份认证协议
    - PAP:明文发送用户名和密码；二次握手；客户端可无限暴破
    - CHAP:3次握手；hash验证；挑战应答机制抗重放攻击
- SSL/TLS
    - SSL使用对称加密传输数据，非对称加密或公钥加密实现对等认证；主要用途是为客户端验证服务器，比如https有那个绿色小锁，你就觉得这个站安全
    - HTTPS替换HTTP,防止无连接状态Web会话轻松被劫持；这里的S一开始就是指SSL,后来TLS是SSL升级版，替换了它，所以现在指TLS
    - TLS是一个两层接口安全协议：TLS记录协议(Record Protocol)/TLS握手协议(Handshake Protocol)
- Callback systems 回拨系统
- Smurf:将回复地址设置为受害者IP，然后广播，然后大家收到广播后，一起给受害者IP发包
---


## **Chapter 5: 信息资产的保护**
- 配置初始化
    - 11 服务器初始配置没有修改
    - 15 端口号未做管理
    - 33 安装网络设备时未变更默认密码
- 21 隐私合规要求，首先应该审查的是法律法规要求
- 27 用VLAN局域网对VoIP进行划分，把语音，视频，其他应用的通信网段划分是最好的
- 信息泄漏
    - 34 a是数据可用性，b是信息泄漏，数据安全性，b的重要性更大
    - 37 生物特征泄露，数据安全性更重要
- 35 还挺特殊的一道题处理方式
- 40 没有接不间断电源，对交换机很危险
- 41 b未加密的密码谁都可以拿，a共享密码还只是内部人员
- 42 cisa和cissp的区别，就是重视工具，b的选项认为人手动处理不可靠
- 69 ca ra 相关知识我还没有吃透




## 考前忠告
1. 一定要仔细读题目的**最后几个字，把它圈出来**:
    - 问的是目标就只找答案跟目标有关；
    - 问的成本就是成本、不管效率什么的；
    - 问质量就找质量，不管什么知识产权隐私之类的；
2. 安全不关注性能，效率一类的词，甚至在Web安全中，可用性也处于三性中的最低地位
3. 答案的高优先级：
    - 人身安全
    - 最高管理层
    - 含有非常绝对词的选项 
4. 成功/失败影响的关键/最主要因素，往往是最开始的部分，比如：
    - 明确范围、标签化
5. 越是技术问题，越要谨慎。毁灭人类的不是无知和弱小，而是傲慢
6. 还有如果这个题，明显送分题，那可能是读题出了问题，把相似但其实不同的词，理解成了一个意思；千万别觉得有送分题，只有你知道这个知识点，它才是送分题，不存在对任何人来说都是的送分题，谨慎！！！
7. 如果遇到不确定的题目，一定要重新读题，然后先筛选错误答案，最后留下两个选项二选一，不要四个选项看第一眼觉得有点熟悉，再看一眼又都觉得有点陌生，然后没过几秒就选了一个答案，经过我的测试，有这种心路历程的题目，几乎都是答错 : )
