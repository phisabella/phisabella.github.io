---
layout: article
title: Basic concepts--AD from 0 to 0.9 part 1
mathjax: true
key: a00005	
cover: /bkgs/1.png
modify_date: 2021-10-3
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

这篇是AD from 0 to 0.9系列笔记的第一部分，主要是有关域，森林，域信任，用户，组的概念和基础<!--more-->

原文： [Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/#why-this-post) 

# 前言

上次被推荐了这篇文章，说是一篇文章讲完了内网，零零散散看了可能有快一个月，总算是看完了一遍。确实学到了很多有关内网的内容，不过文章比较侧重底层和基础一些，还有大量的链接，不容易和实践的记忆联系在一起。上面写的很多内容在自己打靶机或者真实渗透的时候完全感觉不到，但实践的时候看到一些理论相关的又能豁然开朗，可能这就是枯燥的理论学习的意义吧，希望自己的学习不要浮于表层，局限于工具的使用。


（英语原文笔记写着爽但再看的时候完全不想看，因此这个系列完了会把Academy的笔记尽量翻译一次，以后应该也会尽量少做英文的笔记，实在是提不起复习的兴趣）



# 什么是AD

Active Directory是一个系统，它允许管理从中央服务器连接到同一网络中的一组计算机和用户

Active Directory通过维护一个集中化的数据库来管理，其中包含有关用户、计算机、策略等

**装了AD的服务器就是DC**

# **Domains**

首先，我们称之为Active Directory网络的是通常称为域的网络

域是一组连接的计算机，它们共享Active Directory数据库，该数据库由域的中央服务器管理，这些服务器称为**域控制器(DC)**。

## **Domain name**

每个域都有一个 DNS 名称

除了**其** **DNS** **名称**外，每个域名还可以与 NetBIOS 名称进行标识

**SID**（安全标识符）也可以识别域

```powershell
PS C:\Users\Anakin> Get-ADDomain | select DNSRoot,NetBIOSName,DomainSID
DNSRoot         NetBIOSName        DomainSID
-------         -----------        ---------
contoso.local    CONTOSO           S-1-5-21-1372086773-2238746523-2939299801

确认用户域和计算机域
$env:USERDNSDOMAIN
(Get-ADDomain).DNSRoot
(Get-WmiObject Win32_ComputerSystem).Domain
```

# **Forests**

使用 DNS 名称非常有用，因为它允许为管理目的创建子域

```
              contoso.local
                    |
            .-------'--------.
            |                |
            |                |
     it.contoso.local hr.contoso.local
            | 
            |
            |
  webs.it.contoso.local
```

域名树被称为[**Forest**](https://docs.microsoft.com/en-us/windows/win32/ad/forests)，森林的名称与树的根域的名称相同

```powershell
PS C:\Users\Anakin> Get-ADForest

ApplicationPartitions : {DC=DomainDnsZones,DC=contoso,DC=local, DC=ForestDnsZones,DC=contoso,DC=local}
CrossForestReferences : {}
DomainNamingMaster    : dc01.contoso.local
Domains               : {contoso.local}
ForestMode            : Windows2016Forest
GlobalCatalogs        : {dc01.contoso.local, dc02.contoso.local}
Name                  : contoso.local
PartitionsContainer   : CN=Partitions,CN=Configuration,DC=contoso,DC=local
RootDomain            : contoso.local
SchemaMaster          : dc01.contoso.local
Sites                 : {Default-First-Site-Name}
SPNSuffixes           : {}
UPNSuffixes           : {}
```

在森林中，每个域都有自己的数据库和自己的域控制器。但是，**森林中域的用户也可以访问森林的其他域及其资源（默认情况下）**

**能够提供安全隔离的逻辑结构是森林**

## **Functional Modes**

除了 Windows 计算机，域/森林也有自己的"版本"，即所谓的功能模式（ [functional mode](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/raise-active-directory-domain-forest-functional-levels)）

功能模式是以最低要求系统来命名的，即所有电脑系统版本都大于等于功能模式， [functional modes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/564dc969-6db3-49b3-891a-f2f8d0a68a7f)如下：

- Windows2000
- Windows2000MixedDomains
- Windows2003
- Windows2008
- Windows2008R2
- Windows2012
- Windows2012R2
- Windows2016

```powershell
PS C:\Users\Administrator\Downloads> (Get-ADForest).ForestMode
Windows2016Forest
PS C:\Users\Administrator\Downloads> (Get-ADDomain).DomainMode
Windows2016Domain
```

# **Trusts(域信任**)

**同一域森林不同域的用户能相互访问是因为有域信任**

[A trust is a connection from a domain to another](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc731335(v=ws.10))

**域信任是一种授权/身份验证连接**

可以访问其他其他域计算机但不能登陆

## **Trust direction**

信任是一种**有向关系**，其中一方是信任方，另一方是受信任方。建立此链接后，受信任域的用户可以访问受信任域的资源

都是单向的，可以传递

**[trust direction](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc731404(v=ws.10))与访问方向相反**

```
 (trusting)         trusts        (trusted)
  Domain A  -------------------->  Domain B
       outgoing               incoming
       outbound               inbound
                    access
            <--------------------
```

传入的信任允许域的用户访问其他域

```powershell
PS C:\Users\Administrator> nltest /domain_trusts
List of domain trusts:
    0: CONTOSO contoso.local (NT 5) (Direct Outbound) ( Attr: foresttrans )
    1: ITPOKEMON it.poke.mon (NT 5) (Forest: 2) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
    2: POKEMON poke.mon (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

```powershell
PS C:\Users\Anakin> nltest /domain_trusts
List of domain trusts:
    0: POKEMON poke.mon (NT 5) (Direct Inbound) ( Attr: foresttrans )
    1: CONTOSO contoso.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

outbound trust 即对方能访问自己，反之inbound 访问别的域

## **Trust transitivity**

[trust can be transitive or nontransitive](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc754612(v=ws.10))

```
      (trusting)   trusts   (trusted)  (trusting)   trusts   (trusted)
  Domain A  ------------------->  Domain B --------------------> Domain C
                    access                          access
            <-------------------           <--------------------
```

## **Trust types**

AD中的[trust types](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc730798(v=ws.10)#trust-types)：

| **Parent-Child**  | 父域与其子域之间创建的默认域信任                             |
| :---------------- | ------------------------------------------------------------ |
| **Forest**        | 森林之间共享资源的域信任；<br/>林中的任何域都可以访问另一个林中的任何域（如果信任的方向和传递性允许的话）。如果一个林信任配置错误，那么它可以允许[take control of the other forest](http://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/) |
| **External**:     | 连接到非信任森林中特定域的域信任                             |
| **Realm（领域）** | 连接Active Directory和非Windows域的特殊域信任.               |
| **Shortcut**      | 当森林中的两个域经常通信但没有直接连接时，可以通过创建直接快捷方式域信任来避免经过多个域信任 |

## **Trust key**

使用域信任时，域的DC与目标域（或中间域）的DC之间存在通信。通信方式因所使用的协议（NTLM、Kerberos 等）而异，域控制器需要共享一个密钥来保持通信安全

这个密钥就是**域信任密钥**，它在**域信任建立时生成**

创建域信任时，域数据库中会创建 [trust account](https://zer1t0.gitlab.io/posts/attacking_ad/#trust-accounts)，域信任密钥就像用户密码一样存储在账户中（in the [NT hash](https://zer1t0.gitlab.io/posts/attacking_ad/#lm-nt-hash) and [Kerberos keys](https://zer1t0.gitlab.io/posts/attacking_ad/#user-kerberos-keys)）

## More on trusts

一些渗透域信任的链接

- [It’s All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts](https://adsecurity.org/?p=1588)
- [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [Active Directory forest trusts part 1 - How does SID filtering work?](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)
- [Inter-Realm Key Roasting (well… within the first 30 days)](https://blog.xpnsec.com/inter-realm-key-roasting/)
- [Not A Security Boundary: Breaking Forest Trusts](http://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/)

# **Users**

使用Active Directory的关键点之一是用户管理

为了轻松管理活动目录中的用户，中央[数据库](https://zer1t0.gitlab.io/posts/attacking_ad/#database)中将用户存储为对象，可以从域的任何地方（有权利的话）操作和查询

## **User properties**

### **User Identifiers**

**用户名存在SamAccountName** ，SID(Security Identifier)也能用来标识用户

```powershell
PS C:\Users\Anakin> Get-ADUser Anakin

DistinguishedName : CN=Anakin,CN=Users,DC=contoso,DC=local
Enabled           : True
GivenName         : Anakin9
Name              : Anakin
ObjectClass       : user
ObjectGUID        : 58ab0512-9c96-4e97-bf53-019e86fd3ed7
SamAccountName    : anakin
SID               : S-1-5-21-1372086773-2238746523-2939299801-1103
Surname           :
UserPrincipalName : anakin@contoso.local
```

用户SID和域SID很像，其实就是域SID和用户RID (Relative Identifier)的组合

RID 为最后四位 （代表安全主体，比如一个用户、计算机或组）

另外， [LDAP API](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names)使用 `DistinguishedName`来标识对象，因此如果您使用LDAP（这是最常见的方法之一）查询数据库，您可能会通过其`DistinguishedName`看到对对象的引用。

### **User Secrets**

Secret用来验证用户身份，密码会以派生而生成的secrets的形式保存：

- NT hash (and LM hash for the older accounts)
- Kerberos keys

DC可以验证Secrets，域计算机和用户均不能访问Secrets



为了获取用户机密，您需要管理员权限（或同等权限）才能使用

**dcsync**(DCSync是mimikatz在2015年添加的一个功能，能够用来导出域内所有用户的hash) 

从而[dump the domain database](https://zer1t0.gitlab.io/posts/attacking_ad/#domain-database-dumping)，

或从域控制器获取 `C:\Windows\NTDS\ntds.dit`文件。

#### **LM/NT hashes**

[LM and NT hashes ](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4)都存储在Windows本地 [SAM](https://en.wikipedia.org/wiki/Security_Account_Manager)和Active Directory NTDS数据库中，以分别对本地和域用户进行身份验证。这些散列，LM和NT都是**16字节长**。

```
Password: 123456
LM hash: 44EFCE164AB921CAAAD3B435B51404EE
NT hash: 32ED87BDB5FDC5E9CBA88547376818D4
```

[LM hashes are pretty weak](https://en.wikipedia.org/wiki/LAN_Manager#Security_weaknesses)因此在 windows vista/Server 2008后被弃用， [procedure to create an LM hash](https://asecuritysite.com/encryption/lmhash)：

1.密码转换为大写（减少了暴力攻击的搜索空间）

2.不足14位的密码填充null，超过14位的部分被截断（没用）

3.密码分成两部分

4.每部分分别作为DES密钥来加密 KGS!+#$%

5.结果的两个值被连接起来以形成LM散列(你可以分别破解每个部分）

```
upper_password = to_uppercase(password)
14_password = truncate_to_14_bytes(upper_password)

7_part1, 7_part2 = split_7(14_password)

hash1 = des(7_part1, "KGS!+#$%")
hash2 = des(7_part2, "KGS!+#$%")

lm_hash = hash1 + hash2
```

LM哈希好一点，但没有用 [salt](https://en.wikipedia.org/wiki/Salt_(cryptography)) ，所以能被如[rainbow tables](https://en.wikipedia.org/wiki/Rainbow_table)之类的预计算的值破解

用 [MD4](https://en.wikipedia.org/wiki/MD4)（that [is obsolete](https://tools.ietf.org/html/rfc6150)）加密密码的Unicode来计算NT hashes

```
nt_hash = md4(encode_in_utf_16le(password))
```



（NT hash is sometimes called NTLM hash

   NTLM protocol also use hashes, called NTLM hash**es**

   本文的NTLM hash will be a hash of the NTLM protocol）



许多工具允许您提取LM和NT散列，它们通常返回一个包含多行的输出，每个用户一行，格式为<username>:<rid>:<LM>:<NT>::: 

如果未使用LM，其值为aad3b435b51404eeaad3b435b51404ee（空字符串的LM哈希）

```
###Hashes dump format：
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6535b87abdb112a8fc3bf92528ac01f6:::
user:1001:aad3b435b51404eeaad3b435b51404ee:57d583aa46d571502aad4bb7aea09c70:::
```

NT hashes认识很重要，因为可以用

 [Pass-The-Hash](https://zer1t0.gitlab.io/posts/attacking_ad/#pass-the-hash) or [Overpass-the-Hash](https://zer1t0.gitlab.io/posts/attacking_ad/#pass-the-key)  伪造用户

 [hashcat ](https://hashcat.net/)破解LM and NT原密码

#### **Kerberos keys**

Kerberos密钥可用于请求在Kerberos身份验证中代表用户的**Kerberos ticket**，不同密钥有不同用法

| AES 256 key | 最常用，不易触发报警， [AES256-CTS-HMAC-SHA1-96](https://tools.ietf.org/html/rfc3962) |
| ----------- | ------------------------------------------------------------ |
| AES 128 key | Used by the [AES128-CTS-HMAC-SHA1-96](https://tools.ietf.org/html/rfc3962) algorithm |
| DES key     | Used by the [deprecated](https://datatracker.ietf.org/doc/html/rfc6649) [DES-CBC-MD5](https://datatracker.ietf.org/doc/html/rfc3961#section-6.2.1) algorithm. |
| RC4 key     | 用户的[NT hash](https://zer1t0.gitlab.io/posts/attacking_ad/#lm-nt-hashes)， [RC4-HMAC](https://tools.ietf.org/html/rfc4757) |

```bash
###Kerberos keys extracted from the domain database

$ secretsdump.py 'contoso.local/Administrator@192.168.100.2' -just-dc-user anakin
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
contoso.local\anakin:1103:aad3b435b51404eeaad3b435b51404ee:cdeae556dc28c24b5b7b14e9df5b6e21:::
[*] Kerberos keys grabbed
contoso.local\anakin:aes256-cts-hmac-sha1-96:ecce3d24b29c7f044163ab4d9411c25b5698337318e98bf2903bbb7f6d76197e
contoso.local\anakin:aes128-cts-hmac-sha1-96:18fe293e673950214c67e9f9fe753198
contoso.local\anakin:des-cbc-md5:fbba85fbb63d04cb
[*] Cleaning up...
```

这些密钥可用于[Pass-The-Key](https://zer1t0.gitlab.io/posts/attacking_ad/#pass-the-key)攻击来获取伪造的用户票据来在服务认证

### UserAccountControl

用户类的一个有趣属性是 [UserAccountControl](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)(UAC)（和User Account Control mechanism不一样）

用户帐户控制属性包含一**系列与**安全和域非常相关的标志：

| **ACCOUNTDISABLE**                 | 账户被禁用且不能被使用                                       |
| ---------------------------------- | ------------------------------------------------------------ |
| **DONT_REQUIRE_PREAUTH**           | 账户不需要Kerberos预认证                                     |
| **NOT_DELEGATED**                  | 即便被Kerberos认证也无法被委派给服务                         |
| **TRUSTED_TO_AUTH_FOR_DELEGATION** | Kerberos S4U2Self拓展启用，[SeEnableDelegationPrivilege](http://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/) required to modify it |
| **TRUSTED_FOR_DELEGATION**         | 为此帐户及其服务启用Kerberos无约束委派，需要有[SeEnableDelegationPrivilege   ](http://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)才能修改 |

### **Other user properties**

| [Description](https://docs.microsoft.com/en-us/windows/win32/adschema/a-description) | A  description of the user，权限相关，可能会有密码           |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [AdminCount](https://docs.microsoft.com/en-us/windows/win32/adschema/a-admincount) | 是否被[AdminSDHolder](https://adsecurity.org/?p=1906) 保护（可能不会更新，只是参考） |
| [ServicePrincipalName](https://docs.microsoft.com/en-us/windows/win32/adschema/a-serviceprincipalname) | 用户服务， Kerberoast攻击能用到                              |
| [msDS-AllowedToDelegateTo](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/86261ca1-154c-41fb-8e5f-c6446e77daaa) | 能用Kerberos Constrained Delegation 伪造client的服务列表     |
| **MemberOf**                                                 | 用户是其成员的组。此属性是逻辑属性，由组**Members**属性生成。 |
| [PrimaryGroupID](https://docs.microsoft.com/en-us/windows/win32/adschema/a-primarygroupid) | 用户的主要组，这个组不在**MemberOf** 属性中出现              |

## **Important Users**

net user /domain或者powershell能查询

IT team 的用户通常会有高权限

默认情况下内置的**Administrator有最高权限**，可以控制域 [the SID history attack](https://adsecurity.org/?p=1640)能拿forest 

```powershell
PS C:\Users\Anakin> Get-ADUser -Filter * | select SamAccountName

SamAccountName
--------------
Administrator
Guest
krbtgt
anakin
han
POKEMON$
```

**krbtgt** 账户也很重要，它的secrets (NT hash and Kerberos keys)被DC（只被DC使用）用来加密票据**TGTs** (Ticket Granting Ticket),能用来伪造[Golden Tickets](https://en.hackndo.com/kerberos-silver-golden-tickets/)；需要administrator privileges 来dump 域数据库才能拿到**krbtgt** 账户

## **Computer accounts**

域中每台计算机都有自己的用户。

用户账户和计算机账户区别

| 用户账户   | 以[User class](https://docs.microsoft.com/en-us/windows/win32/adschema/c-user)形式存储在数据库 |
| ---------- | ------------------------------------------------------------ |
| 计算机账户 | [Computer   class](https://docs.microsoft.com/en-us/windows/win32/adschema/c-computer)，是User class的子class  账户名为主机名，以$结尾 |

```powershell
PS C:\> Get-ADObject -LDAPFilter "objectClass=User" -Properties SamAccountName | select SamAccountName

SamAccountName
--------------
Administrator
Guest
DC01$
krbtgt
anakin
WS01-10$
WS02-7$
DC02$
han
POKEMON$
```

根据名字或者描述（可能有密码）能获得很多有用信息

The [Find-DomainObjectPropertyOutlier](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993) Cmdlet of [Powerview](https://github.com/BC-SECURITY/Empire/blob/master/data/module_source/situational_awareness/network/powerview.ps1) 可以用来找信息

## **Trust accounts**

创建域信任时自动创建，名字为另一个域的NetBIOS 名，以$结尾，存储 trust key（NT hash or Kerberos keys 中的一个），会在 `Get-ADUser` and `Get-ADObject`两个里面出现

名字为对方域名(foo域信任账户为bar$,bar为foo$)

```powershell
PS C:\> Get-ADUser  -LDAPFilter "(SamAccountName=*$)" | select SamAccountName

SamAccountName
--------------
POKEMON$
```

如果能拿到域信任账户的[secrets](https://zer1t0.gitlab.io/posts/attacking_ad/Domain database dumping)，就可以创建[inter-realm Kerberos tickets](https://adsecurity.org/?p=1588)

# **Groups**

[groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#default-security-groups)

组存在域数据库里，能被SamAccountName属性标识，或SID

```powershell
PS C:\Users\Anakin> Get-ADGroup -Filter * | select SamAccountName

SamAccountName
--------------
Administrators
Users
Guests
<-- stripped output -->
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Cert Publishers
Domain Admins
Domain Users
<-- stripped output -->
Protected Users
Key Admins
Enterprise Key Admins
DnsAdmins
DnsUpdateProxy
DHCP Users
DHCP Administrators
```

## **Important groups**

### **Administrative groups**

AD里有许多 [default groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#default-security-groups)定义域/森林不同角色，[Domain Admins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-domainadmins) group应该最重要。

```powershell
PS C:\Users\Anakin> Get-ADGroup "Domain Admins" -Properties members,memberof


DistinguishedName : CN=Domain Admins,CN=Users,DC=contoso,DC=local
GroupCategory     : Security
GroupScope        : Global
MemberOf          : {CN=Denied RODC Password Replication Group,CN=Users,DC=contoso,DC=local,
                    CN=Administrators,CN=Builtin,DC=contoso,DC=local}
Members           : {CN=Administrator,CN=Users,DC=contoso,DC=local}
Name              : Domain Admins
ObjectClass       : group
ObjectGUID        : ac3ac095-3ea0-4922-8130-efa99ba99afa
SamAccountName    : Domain Admins
SID               : S-1-5-21-1372086773-2238746523-2939299801-512
```

[Enterprise Admins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-entadmins) group有更多权限，能在所有森林中拥有管理权

Enterprise Admins只存在于域森林根域，默认添加到所有域的[Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#administrators) group

```
###Administrators groups memberships in forest######
####################################################
                        .------------------------.
                        |     contoso.local      |
       .-------------------------------------------------------------.
       |                                                             |
       |                   .----------------.                        |  
       |               .-->| Administrators |<-.   .->Administrators |
       |               |   '----------------'  |   |     ____        | 
       |               |    .---------------.  |   |    |    |       |
       |               |    | Domain Admins |>-'---'    |____|       |
       |               |    '---------------'           /::::/       |
       |               |   .-------------------.                     |
       |               '--<| Enterprise Admins |                     |
       |                   '-------------------'                     |
       |                             v v                             |
       '-----------------------------|-|-----------------------------'  
                           |         | |      |                         
                           |         | |      |                         
                 .---------'         | |      '-----------.             
                 |                   v v                  |             
.----------------------------------. | | .----------------------------------.
|        it.contoso.local          | | | |        hr.contoso.local          |
|----------------------------------| | | |----------------------------------|
|                                  | v v |                                  |
|        .----------------.        | | | |        .----------------.        |
|     .->| Administrators |<---------' '--------->| Administrators |<-.     |
|     |  '----------------'        |     |        '----------------'  |     |
|     |  .---------------.         |     |        .---------------.   |     |
|     '-<| Domain Admins |         |     |        | Domain Admins |>--'     |
|        '---------------'         |     |        '---------------'         |
|                |                 |     |                |                 |
|        .-------'---------.       |     |        .-------'---------.       |
|        |                 |       |     |        |                 |       |
|        v                 v       |     |        v                 v       |
| Administrators    Administrators |     | Administrators    Administrators |
|       ____              ____     |     |      ____              ____      |
|      |    |            |    |    |     |     |    |            |    |     |
|      |____|            |____|    |     |     |____|            |____|     |
|      /::::/            /::::/    |     |     /::::/            /::::/     |
'----------------------------------'     '----------------------------------'
```

### **Other important groups**

other [important groups](https://adsecurity.org/?p=3700)

| **DNSAdmins**                   | [DNSAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins)能允许成员可用任意DLL [execute   code in Domain Controllers](https://www.semperis.com/blog/dnsadmins-revisited/) |
| ------------------------------- | ------------------------------------------------------------ |
| **Protected Users**             | [Protected Users](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)组，增强安全，成员**不允许**：<br/> ~~1. 用NTLM认证（仅限Kerberos）<br/> 2.Kerberos预认证用DES或者RC4加密类型 <br/> 3.被约束委托或非约束委托<br/> 4.在最初的四小时生存期之后续约Kerberos TGT。~~  <br/>能防止 [NTLM relay](https://en.hackndo.com/ntlm-relay/) or [Kerberos   Delegation](https://www.tarlogic.com/en/blog/kerberos-iii-how-does-delegation-work/) attacks |
| **Schema Admins**               | [Schema Admins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#schema-admins)  **能修改AD [database](https://zer1t0.gitlab.io/posts/attacking_ad/#database) **schema |
| **Account Operators**           | [Account Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators)， 修改域中许多组中的用户（管理不行），但可以修改Server Operators组 |
| **Backup Operators**            | [Backup Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#backup-operators)，能备份恢复DC文件，能登陆DC，可以借此修改DC中的文件 |
| **Print Operators**             | [Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#print-operators)，  能登陆DC |
| **Server Operators**            | [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#server-operators)，  能登陆DC且修改配置文件 |
| **Remote Desktop Users**        | [Remote Desktop Users](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-remotedesktopusers)，  能通过[RDP](https://zer1t0.gitlab.io/posts/attacking_ad/#rdp)登陆DC |
| **Group Policy Creator Owners** | [Group Policy Creator Owners](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#group-policy-creator-owners)，能编辑域[GPOs](https://zer1t0.gitlab.io/posts/attacking_ad/#group-policy)（Group Policy Objects） |

还有很多[groups described in Microsoft docs](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#replicator)

许多软件（微软）能自己添加用户组，如 [Exchange](https://zer1t0.gitlab.io/posts/attacking_ad/#exchange)可以[add privileged groups](https://adsecurity.org/?p=4119) 如Exchange Windows Permissions组，可用来实施DCSync攻击（如果没有正确升级/同步？）

## **Group Scope**

AD中根据[their scope](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#group-scope)可以把组分为三类：

| 通用组（Universal ）  | 可以有同域森林的用户，并在相同林和域信任林中赋予用户权限，如Enterprise Admins |
| --------------------- | ------------------------------------------------------------ |
| 全局组（**Global** ） | 只能具有相同域的成员，并在相同林或信任域或林的域中授予权限，如 Domain Admins |
| 域本地组              | 可以具有来自域或任何受信任域的成员，并仅在其域中授予权限，如Administrators |

域组（及其域用户）也可以是计算机本地组的成员 ,例如，默认情况下，域管理员组会添加到计算机的管理员本地组。