---
layout: article
title: Logon+Auth+GP--AD from 0 to 0.9 part 7
mathjax: true
key: a00011
cover: /bkgs/1.png
modify_date: 2021-10-6
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

这篇是AD from 0 to 0.9系列笔记的第七部分，主要是**Logon types和Authorization以及Group Policy**相关<!--more-->

原文： [Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/#why-this-post) 

# **Logon types**

首先，不是每种登陆都可以被任何用户使用。其次，[many logons cache credentials in the lsass process](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types) ，甚至在LSA secrets中缓存凭证，这些凭证可以由攻击者恢复，因此识别哪些属于这种登录很重要

## **Interactive logon**

交互登录或本地登录发生在物理计算机中有登录时，或使用runas时。凭证缓存在计算机的lsass进程中。

```powershell
###Interactive logon with runas
runas /user:<username> cmd
```

（Interactive logon with runas）

在这种登录类型中，对于本地帐户，计算机通过检查其NT哈希值与存储在SAM中的哈希值来检查密码。如果用户使用的是域帐户，则计算机通过向计算机中缓存的域控制器请求Kerberos TGT来检查用户凭据，如果DC不可达，计算机检查在Domain cached credentials (DCC)的用户凭证，DCC缓存的用户凭证是最后一次 [domain users logged in the machine ](https://docs.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/cached-domain-logon-information)，如果没缓存就不会认证

一旦认证完成，NT hash（来源密码）存在lsass进程里。对域账户来说还包括Kerberos密钥（也来源于用户密码）和票据，它们被缓存来提供SSO(Single Sign On)，老式电脑里还会存明文密码

应该需要 [SeInteractiveLogonRight ](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-locally)才能交互式登陆，尤其是DC或其他Windows服务器上。

## **Network logon**

网络登录发生在用非交互服务（如SMB、RPC、SQL等）连接到远程计算机时，这种登陆需要密码，NT hash，或Kerberos票据，因此容易被Pass-The-Hash, Pass-The-Key or Pass-The-Ticket attack，要注意**凭证不被远程机器缓存**，除非能Kerberos delegation

这是经常被攻击的登陆方式（因为这也是正常登录最常用的，因为计算机在一个域中不断地相互连接）

([Psexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), the [impacket](https://github.com/SecureAuthCorp/impacket) suite and Powershell remote（using WinRM with default login）即便能交互式也会网络登陆)

```powershell
###Access to a share
dir \\ws01-10\Temp
###Execute PsExec
.\PsExec.exe \\dc01 cmd
```

这种登陆方式客户端远程连接机器并用 [SPNEGO](https://zer1t0.gitlab.io/posts/attacking_ad/#spnego)协商认证协议，决定用 [Kerberos](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos) or [NTLM](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm)。由于任意一种方式都不是直接发送凭证因此无法缓存，除非[Kerberos delegation](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos-delegation) is enabled

即便能登也不一定能用，因为防火墙不让远程连接或者只能管理员远程登陆

比如，或许能登上某个远程计算机访问共享，但不能用PsExec 打开shell，因为需要能访问service Manager，而这只能有admin访问。

## **Batch logon（**批处理登录？）

Microsoft文档表明任务用户的密码存储在LSA机密中（但作者无法在测试中存储密码）。此外，在执行任务时，凭据将缓存在lsass进程中。

```powershell
###Task creation with user credentials
schtasks.exe /create /tn notepaddaily /tr notepad.exe /sc daily /ru CONTOSO\TaskUser /rp task1234!
```

请注意，批登录将在执行任务时生成，而不是在创建任务时生成。因此，您可能有权限将批处理当任务运行（如[SeBatchLogonRight](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/log-on-as-a-batch-job)），但无法创建任务。例如， Backup Operators有SeBatchLogonRight，但他们无法创建任务（默认情况下）

任务执行时凭证被验证并和交互式登陆一样缓存

## **Service logon**

当服务将在当前用户环境中启动时，使用服务登录；明文密码存储在机器的LSA机密中，当执行服务时，凭证将缓存在lsass进程中

```powershell
###Service creation with user credentials
sc.exe create MySvc2 binpath= c:\windows\system32\notepad.exe obj=CONTOSO.local\svcUser password=svc1234!
```

注意服务登录在服务执行而不是创建时，因此有权限作为服务登陆(like [SeServiceLogonRight](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/log-on-as-a-service))不一定能创建服务

## **NetworkCleartext logon**

密码通过网络发送到目标机器（在加密通信中），这种登陆在CredSSP 认证指定是由Powershell remoting使用

（CredSSP使用NTLM或Kerberos执行网络身份验证，并在创建加密通道时，将密码发送到目标计算机。）

由于凭证在通信中发出，因此也会被缓存在目标机器

```powershell
###NetworkCleartext logon with Powershell remoting
New-PSSession -Credential $(Get-Credential) -Authentication Credssp
```

## **NewCredentials logon**

用带 /netonly的[runas ](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc771525(v=ws.11))时，然后，启动的进程将仅对远程连接使用凭据，并保持当前用户会话用于本地操作

凭证缓存在本地lsass进程以用来网络连接，然后进程需要时就可以网络登陆来拿域的远程资源

```cmd
###Perform a NewCredentials logon with runas
runas /netonly /user:CONTOSO\OtherUser cmd
```

在完成网络连接之前不会检查凭据，但在执行runas命令时会缓存凭据，就像在 [Interactive Logon](https://zer1t0.gitlab.io/posts/attacking_ad/#interactive-logon)中一样（Kerberos票证除外，因为它们是在检查凭据时检索的）。您必须考虑到这一点，因为此方法**允许在lsass进程中缓存假凭据**，and is sometimes [used by the blue team to create honey credentials](https://securitywa.blogspot.com/2016/04/improve-detection-using-honeycreds.html)以检测攻击者。

## **RemoteInteractive logon**

[RDP](https://zer1t0.gitlab.io/posts/attacking_ad/#RDP)的时候用，RDP用 [CredSSP](https://zer1t0.gitlab.io/posts/attacking_ad/#cred-ssp) 来远程登陆，凭证会缓存在远程lsass进程

认证和网络登陆类似，但凭证送到目标机器因此和交互式登陆缓存相似

要能用RemoteInteractive 登陆远程机器，用户需要在[Remote Desktop Users](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-remotedesktopusers)组，或在目标机器有[SeRemoteInteractiveLogonRight](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services)权限

# **Authorization**

一旦客户端能够解析目标主机名并获得身份验证，目标服务/程序/计算机现在应该知道其权限，即知道用户用户名和SID，以及它所属的组。一旦知道这些信息，程序就可以决定用户是否有足够的权限访问某些对象。

## **ACLs（**访问控制列表**）**

### **Security descriptor（**安全描述符**）**

但是，如何检查用户是否有权访问对象呢？通过检查用户[security descriptor](http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm)，在AD中每个数据库对象在[NTSecurityDescriptor](https://docs.microsoft.com/en-us/windows/win32/adschema/a-ntsecuritydescriptor)属性都有一个关联的 [security descriptor](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors)，以 [binary format](https://www.gabescode.com/active-directory/2019/07/25/nt-security-descriptors.html)存储但能被翻译成[Security Descriptor String Format](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)。

安全描述符包括如下安全信息：

- 对象拥有者的**主体**SID 
- 拥有者**primary group**的SID
- （可选）**DACL**（Discretionary Access Control List，自主访问控制列表）
- （可选）**SACL**（System Access Control List，系统访问控制列表）

```powershell
###Get security descriptor of user object
PS C:\> $(Get-ADUser anakin -Properties nTSecurityDescriptor).nTSecurityDescriptor | select Owner,Gro
up,Access,Audit | Format-List

Owner  : CONTOSO\Domain Admins
Group  : CONTOSO\Domain Admins
Access : {System.DirectoryServices.ActiveDirectoryAccessRule, System.DirectoryServices.ActiveDirectoryAccessRule,
         System.DirectoryServices.ActiveDirectoryAccessRule, System.DirectoryServices.ActiveDirectoryAccessRule...}
Audit  :
```

每个安全描述符中可能有两个ACL，DACL和SACL，ACL是ACE（Access Control Entry，访问控制条目）的列表。SACL的ACEs定义了将要[generate logs](https://docs.microsoft.com/en-us/windows/win32/secauthz/audit-generation)的访问尝试，从防御角度来看，它们非常有用

但最重要的部分是DACL，一般所有对象都有，其ACE决定了可以访问对象的用户/组以及允许的访问类型，一般说到对象ACL的时候指的就是DACL

### **ACEs**

Each [ACE has several parts](http://web.archive.org/web/20150907161422/http:/searchwindowsserver.techtarget.com/feature/The-structure-of-an-ACE):

| **ACE类型**                     | 指定ACE是否用于允许或拒绝访问（或在SACL情况下记录访问）。    |
| ------------------------------- | ------------------------------------------------------------ |
| **继承Inheritance**             | 指示是否继承ACE。                                            |
| **主体/标识Principal/Identity** | 表示应用ACE的主体（用户/组）。主体SID已存储。                |
| **权限Rights**                  | 指示ACE正在应用的访问类型。                                  |
| **对象类型Object  type**        | 根据Access Mask标志指示扩展权限、属性或子对象的 [GUID](https://en.wikipedia.org/wiki/Universally_unique_identifier)。未使用则设置为0 |
| **继承类型Inheritance  type**   | 可以从此对象继承ACE的对象类的类型。                          |

```powershell
###ACE of user account
PS C:\Users\Administrator> $(Get-ADUser anakin -Properties nTSecurityDescriptor).nTSecurityDescriptor.Access[0]

ActiveDirectoryRights : GenericRead
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SELF
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
```

因此**ACEs能授予/限制访问权限**，如果主体体同时被不同的ACE允许和拒绝访问，那么**拒绝优先**

另一方面，**ACE可以从数据库的父对象（OU和容器）继承**，实际上，应用于对象的大多数ACE都是继承的。如果继承的访问与显式ACE（非继承）冲突，则显式ACE确定访问规则。因此，ACE的优先顺序如下：

1. Explicit deny ACE
2. Explicit allow ACE
3. Inherited deny ACE
4. Inherited allow ACE

有一种特殊情况不受ACEs的限制，即对象**owner**。**所有者具有修改对象的ACE的隐式权限**（WriteDacl权限）

还有一种情况，如果安全描述符没有DACL（设置为NULL），任何人都能访问该对象，如果是空DACL（DACL没有ACEs），就没有人能访问

### **Rights**

可以在ACE中指定以下权限：

| Delete                | 删除对象。                                                   |
| --------------------- | ------------------------------------------------------------ |
| ReadControl           | 读取安全描述符，SACL除外。                                   |
| WriteDacl             | 修改安全描述符中的对象DACL。                                 |
| WriteOwner            | 修改安全描述符中的对象所有者。                               |
| CreateChild           | 创建子对象。用于容器。                                       |
| DeleteChild           | 删除子对象。用于容器。                                       |
| ListContents          | 列出子对象。用于容器。如果未授予此权限或ListObject，则该对象对用户隐藏。 |
| ReadProperty          | 读取对象类型中指定的属性或 [property   set](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/177c0db5-fa12-4c31-b75a-473425ce9cca) 。如果对象类型为零，则可以读取所有属性。它不允许读取 [confidential   properties](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7c1cdf82-1ecc-4834-827e-d26ff95fb207)。 |
| WriteProperty         | 修改对象类型中指定的属性。如果对象类型为零，则可以修改所有属性。 |
| WritePropertyExtended | 执行 [validated   write](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/20504d60-43ec-458f-bc7a-754eb64446df)。也许最有趣的 [validated   write](https://docs.microsoft.com/en-us/windows/win32/adschema/validated-writes) 是组的[Self-Membership](https://docs.microsoft.com/en-us/windows/win32/adschema/r-self-membership)，它允许带着ACE将当前用户添加到组中。 |
| DeleteTree            | 通过删除树操作删除所有子对象。                               |
| ListObject            | 列出对象。如果未授予此权限或ListContents，则对象对用户隐藏。 |
| ControlAccess         | 可以根据对象类型以多种不同方式解释的特殊权限。如果对象类型是[confidential   property](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e6685d31-5d87-42d0-8a5f-e55d337f47cd)的GUID，则会授予读取权限。如果是在数据库架构中注册的 [extended   right](https://docs.microsoft.com/en-us/windows/win32/adschema/extended-rights)的GUID，则给出该权限。如果对象类型为null（GUID为全零），则授予所有扩展权限。 |

还有一些通用权利，包括若干权利：

- **GenericRead**: ReadControl,     ListContents, ReadProperty (all), ListObject.
- **GenericWrite**: ReadControl,     WriteProperty (all), WritePropertyExtended (all).
- **GenericExecute**: ReadControl,     ListContents.
- **GenericAll**: Delete,     WriteDacl, WriteOwner, CreateChild, DeleteChild, DeleteTree, ControlAccess     (all), GenericAll, GenericWrite.

也有很多 [extended rights](https://docs.microsoft.com/en-us/windows/win32/adschema/extended-rights)，但最有意思的是以下：

| [User-Force-Change-Password](https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password) | 在不知道当前密码的情况下更改用户密码。对于用户对象。不要混淆[User-Change-Password](https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password)，这需要知道密码才能更改它。 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [DS-Replication-Get-Changes](https://docs.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes) | 复制数据库数据。对于域对象。需要执行dcsync。                 |
| [DS-Replication-Get-Changes-All](https://docs.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all) | 复制数据库机密数据。对于域对象。需要执行dcsync。             |

```powershell
###DS-Replication-Get-Changes-All right in domain
PS C:\Users\Administrator\Downloads> (Get-Acl 'AD:\DC=contoso,DC=local').Access[49]

ActiveDirectoryRights : ExtendedRight
InheritanceType       : None
ObjectType            : 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : CONTOSO\Domain Controllers
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
```

### **ACL attacks**

域中有大量的ACLs，导致很难管理，可能会有[several misconfigurations](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)并导致攻击者能在域甚至域森林中 [elevate privileges](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)（域森林中域都是相连的，可以添加指向其他域主体的ACE），错配例子如下：

| 更改用户密码                                                 | 如果您对用户对象拥有User-Force-Change-Password or GenericAll权限，则可以改密码。 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| 使用户Kerberoasteable                                        | 如果可以在用户的**ServicePrincipalName**属性中写入SPN，则可以对该帐户执行 [Kerberoast](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)攻击，并尝试破解其密码。要编写SPN，需要使用WritePropertyExtended或GenericWrite或GenericAll对 [Validated-SPN](https://docs.microsoft.com/en-us/windows/win32/adschema/r-validated-spn)进行验证写入。 |
| 执行恶意脚本                                                 | 如果可以使用WriteProperty、GenericWrite或GenericAll修改用户的ScriptPath属性，则可以设置恶意文件，该文件将在用户下次登录时执行。您可以使用[an UNC path   to point to a share](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces#genericwrite-on-user)。可能还需要启用UserAccountControl属性的**SCRIPT** 标志。 |
| 将用户添加到组                                               | 如果可以使用WriteProperty、GenericWrite或GenericAll修改组的**members**属性，则可以将任何成员添加到组中。如果您有Self-Membership权限，您可以将当前用户添加到该组中。 |
| [Kerberos   RBCD attack](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution) | 如果您可以使用WriteProperty、GenericWrite或GenericAll修改计算机账户的 msDS-AllowedToActOnBehalfOfOtherIdentity，则您可以为另一个用户启用基于Kerberos RBCD，使其访问计算机服务，并最终以管理员身份访问计算机。 |
| [LAPS   password](https://adsecurity.org/?p=3164)            | 如果您可以读取LAPS用于存储计算机本地管理员密码的**ms-Mcs-AdmPwd**计算机机密属性，则您可以将其读取为计算机的本地管理员访问权限。通过检查计算机帐户中是否存在**ms-Mcs-AdmPwdExpirationTime**属性，可以识别计算机中LAPS的使用情况。 |
| [DCSync   attack](https://adsecurity.org/?p=1729)            | 如果您拥有 DS-Replication-Get-Changes 和 DS-Replication-Get-Changes-All 对域对象的所有扩展权限，则可以执行DCSync攻击以dump 数据库内容。 |
| GPO滥用                                                      | 如果可以使用WriteProperty、GenericWrite或GenericAll修改[Group   Policy Container](https://zer1t0.gitlab.io/posts/attacking_ad/#group-policy-container) 的 GPC-File-Sys-Path，则可以修改GPO并在受GPO影响的计算机中执行代码。 |
| 修改ACL                                                      | 如果您拥有WriteDacl权限（或GenericAll），则可以创建ACE来授予对象中的任何权限，并执行以前的一些攻击。此外，如果您具有WriteOwner权限，由于所有者对象具有隐式WriteDacl权限，您可以将对象所有者更改为您的用户，然后修改ACL。 |

ACL不仅能提权，还能 [create backdoors](https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)，可以参考 [An ACE Up the Sleeve](https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

#### **AdminSDHolder**

可能最有趣的持久性技巧之一是修改**AdminSDHolder** 对象，AdminSDHolder 是数据库中的一个特殊对象，其DACL用作特权主体安全描述符的模板

```powershell
###The AdminSDHolder object
PS C:\> Get-ADObject 'CN=AdminSDHolder,CN=system,DC=contoso,DC=local'

DistinguishedName                              Name          ObjectClass ObjectGUID
-----------------                              ----          ----------- ----------
CN=AdminSDHolder,CN=system,DC=contoso,DC=local AdminSDHolder container   7f34e8a5-ffbd-474a-b436-1e02b7b49984
```

每隔60分钟，SDProp（Security Descriptor Propagator 安全描述符传播程序）检查这些特权主体的安全描述符，并将其DACL替换为AdminSDHolder DACL的副本（如果它们不同）。这样做是为了防止修改这些主体的DACL，但 if you are [able to add custom ACEs](https://adsecurity.org/?p=1906)到AdminSDHolder DACL，则这些新的ACE也将应用于受保护的主体。

默认情况下，以下主体由AdminSDHolder“保护”：

- [Account Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#account-operators)

- Administrator

- [Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#administrators)
- [Backup Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#backup-operators)
- [Domain Admins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#domain-admins)
- [Domain Controllers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#domain-controllers)
- [Domain Guests](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#domain-guests)
- [Enterprise Admins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#enterprise-admins)
- [Enterprise Key      Admins](https://zer1t0.gitlab.io/posts/attacking_ad/Enterprise Key Admins)
- [Enterprise      Read-Only Domain Controllers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#enterprise-read-only-domain-controllers)
- [Key Admins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#key-admins)

- krbtgt

- [Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#print-operators)
- [Read-only Domain      Controllers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#enterprise-read-only-domain-controllers)
- [Replicator](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#replicator)
- [Schema Admins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#schema-admins)
- [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#server-operators)

## **Privileges**

Windows用户权限可以允许用户绕过对象的ACL执行操作，例如，Windows机器中的SeDebugPrivilege允许在机器的任何进程内存中读/写，即使您没有权限

AD中[some privileges can be also abused](https://adsecurity.org/?p=3700)（主要在AD）：

**SeEnableDelegationPrivilege**

​	[SeEnableDelegationPrivilege ](http://www.harmj0y.net/blog/activedirectory/the-most-dangerou			s-user-right-you-probably-have-never-heard-of/)必须在域控制器中为用户设置（是本地权限），然后它允许修改用户的 [msDS-AllowedToDelegateTo](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/86261ca1-154c-41fb-8e5f-c6446e77daaa)属性以及UserAccountControl属性中**TRUSTED_FOR_DELEGATION** and **TRUSTED_TO_AUTH_FOR_DELEGATION**标志。换句话说，SeEnableDelegationPrivilege 		[allows to control the Kerberos Unconstrained and Constrained Delegation](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enable-computer-and-user-accounts-to-be-trusted-for-delegation) options of the domain，攻击者可以使用这些选项升级权限。默认情况下，仅提供给管理员帐户

**SeBackupPrivilege**

​	 [backup privilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories)允许读DC任意文件来备份它们，可能会被拿来读域数据库；默认赋给**Backup Operators**, **Server Operators** and **Administrators组**

​	这个权限只有在用 [NTFS backup API](https://docs.microsoft.com/en-us/windows/win32/backup/backup-reference)的时候才有效，这可以通过 [wbadmin](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin) utility or [Powershell WindowsServerBackup](https://docs.microsoft.com/en-us/powershell/module/windowsserverbackup/?view=windowsserver2019-ps)（都需要[Windows Server Backup ](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/jj614621(v=ws.11))特	性） 来访问。也可以also use [reg save](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-save) to [access to the SAM and LSA secrets](https://zer1t0.gitlab.io/posts/attacking_ad/#dumping-registry-credentials)

**SeRestorePrivilege**

​	 [restore privilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories)允许从备份中在DC中写任何文件，这允许攻击者修改域数据库；默认会给**Backup 	Operators**, **Server Operators** and **Administrators** 	**组**

**SeTakeOwnershipPrivilege**

​	有[take ownership privilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)就能拿机器 [ownership of securable objects](https://docs.microsoft.com/en-us/windows/win32/secauthz/securable-objects)，如文件、进程或

​	注册表项，对象所有者始终可以修改对象权限（WriteDacl），例如，可以用 [SetNamedSecurityInfo](https://github.com/hatRiot/token-priv/blob/7cd22e35a4ec4597aa9749985780fd491d9af30a/poptoke/poptoke/SeTakeOwnershipPrivilege.cpp#L31) 	API 调用来获取对象所有权

​	该怎么获取AD数据库对象所有权？？？（作者的疑惑？）

除了在域中使用的权限外，了解[dangerous privileges](https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/)对于提升Windows计算机中的权限也很有用。通常使用以下方法：

**SeDebugPrivilege**

​	用户可以调试机器中的任何进程，因此它可以在任何进程中插入代码，这可能导致权限提升，或者读取进程的内存，从而允许读取登录机器的用户的lsass进程	机密（可使用 [mimikatz](https://github.com/gentilkiwi/mimikatz)）

**SeImpersonatePrivilege**

​	用户可以获取机器中其他用户的 [security tokens](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt#L155)。如果模拟令牌级别为SecurityDelegation，则用户可以使用该令牌在域的其他计算机中模拟目标用户	（SecurityDelegation令牌与可在网络连接中使用的Kerberos票证等用户凭据相关联）。如果模拟令牌级别为SecurityImpersonation，则只能在本地计算机中模	拟目标用户（提权很有用）。

​	SeImpersonatePrivilege授予“NT AUTHORITY\Network Service”（通常用于运行web服务器之类的），因此，如果能渗透web服务器，或许能使用 [incognito](https://labs.f-secure.com/archive/incognito-v2-0-released/)在	网络上模拟某些域用户。但肯定的是，如果您想在本地机器中使用SeImpersonatePrivilege提升特权，请使用 [potato](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)。

​	还有其他特权可用于提升Windows机器中的特权，Foxglof的 [token-priv ](https://github.com/hatRiot/token-priv)repository包括一篇描述这些特权的文章和利用这些特权的POC，强烈推荐该资源。

# Group Policy

AD的目标是管理组织的计算机和用户，部分管理过程由组策略执行

组策略是一种允许将一组规则/操作应用于AD网络用户和计算机的机制。基本能设置所有能想到的内容

要定义规则，可以创建Group Policy Objects (GPOs)，每个GPO定义了一系列适用于特定机器和域的策略，也能创建应用于整个计算机或用户会话的策略。例如在计算机启动或用户登录时执行脚本

## **GPO Scope**

创建GPO时，需要指定[which computers is going to be applied](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581922(v=ws.11)#scope)。为此，您需要将GPO链接到以下数据库容器之一：

- Domain
- Organizational Unit (OU)

- [Site](https://docs.microsoft.com/en-us/windows/win32/adschema/c-site) (容器，用于包含物理上接近的计算机组，不建议用于GPO）

Windows机器也可以有本地组策略，不同的GPO能以不同优先级应用到电脑上（上面优先级低）：

1. Local
2. Site
3. Domain
4. Organizational Unit

当然AD GPO（没有本地的）可能会设置*No Override* 的规则。因此，如果设置了域策略规则，OU中的任何规则都不能与上级规则冲突

此外，GPO可以关联 [WMI query](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/create-wmi-filters-for-the-gpo)，该查询允许筛选将应用GPO的计算机。例如，仅将策略应用于Windows 7计算机。

域中计算机每90分钟都会查询一次组策略更新，除了DC（5分钟一次）， [gpupdate](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/gpupdate)能立刻更新

每个GPO有GUID标识并由两部分组成：组策略模板和组策略容器

## **Group Policy template**

组策略模板是SYSVOL共享中的一个目录，模板在 \ \<domain>\SYSVOL\<domain>\Policies\ 能找到，每个模板目录用GPO GUID命名

```powershell
###List of GP templates
PS C:\> ls \\contoso.local\SYSVOL\contoso.local\Policies\

    Directory: \\contoso.local\SYSVOL\contoso.local\Policies


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/28/2020  10:02 AM                {31B2F340-016D-11D2-945F-00C04FB984F9}
d-----       11/28/2020  10:02 AM                {6AC1786C-016F-11D2-945F-00C04fB984F9}
d-----        4/19/2021   5:12 PM                {BE864EFE-6C07-4A53-A9D8-7EB6EB36BE5A}
```

每个GPO 文件都有：

- 计算机目录：用于计算机级策略。
- 用户目录：用于用户级策略。
- GPT.INI：关于GPO的基本信息，版本和显示名。

然后，在[these directories](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759367(v=ws.10)?redirectedfrom=MSDN#subfolders-of-the-group-policy-template)下可以找到非常不同的文件和目录，您可以在其中找到配置INI文件，这些文件指定要执行的注册表项值、组成员或脚本。而且，如果幸运的话，能找到一些带有 cpassword tags的 [credentials in scripts or Group Policy Preferences (GPP) files](https://adsecurity.org/?p=2288)。您可以使用 [Get-GPPPasword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)脚本来搜索GPP凭据。

（ [Group Policy Preferences](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581922(v=ws.11)#scope)是用于在Windows Server 2008中添加的一组新策略的名称）

## **Group Policy container**

为了允许计算机定位组策略模板，AD数据库存GPOs数据在CN=Policies,CN=System,DC=<domain>,DC=<com>容器。每个GPO都存在一个包含GUID GPO和GP模板的路径的 [GroupPolicyContainer](https://docs.microsoft.com/en-us/windows/win32/adschema/c-grouppolicycontainer)对象里

```powershell
###List domain GPOs
PS C:\> Get-ADObject -LDAPFilter "(ObjectClass=GroupPolicyContainer)" -Properties Name, DisplayName,gPCFileSysPath | select Name, DisplayName,GPCFileSysPath | Format-List

Name           : {31B2F340-016D-11D2-945F-00C04FB984F9}
DisplayName    : Default Domain Policy
GPCFileSysPath : \\contoso.local\sysvol\contoso.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}

Name           : {6AC1786C-016F-11D2-945F-00C04fB984F9}
DisplayName    : Default Domain Controllers Policy
GPCFileSysPath : \\contoso.local\sysvol\contoso.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}

Name           : {BE864EFE-6C07-4A53-A9D8-7EB6EB36BE5A}
DisplayName    : test policy
GPCFileSysPath : \\contoso.local\SysVol\contoso.local\Policies\{BE864EFE-6C07-4A53-A9D8-7EB6EB36BE5A}
```

要注意，GPO GUID与用于标识Active Directory数据库中每个对象的GUID不同。还请注意，如果您能够编辑GPO的 [GPCFileSysPath](https://docs.microsoft.com/en-us/windows/win32/adschema/a-gpcfilesyspath)属性，则可以设置一个由您控制的路径，并创建一个恶意GPO，其中可能包含将在多台计算机上执行的恶意脚本。

另一方面，域、OU和站点的数据库对象通过使用 [GpLink](https://docs.microsoft.com/en-us/windows/win32/adschema/a-gplink)属性链接到GPO。

```powershell
###List domains and OUs with linked GPOs
PS C:\> Get-ADObject -LDAPFilter '(gPLink=*)' -Properties CanonicalName,gpLink | select objectclass,CanonicalName,gplink | Format-List

objectclass   : domainDNS
CanonicalName : contoso.local/
gplink        : [LDAP://cn={BE864EFE-6C07-4A53-A9D8-7EB6EB36BE5A},cn=policies,cn=system,DC=contoso,DC=local;1][LDAP://C
                N={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=contoso,DC=local;0]

objectclass   : organizationalUnit
CanonicalName : contoso.local/Domain Controllers
gplink        : [LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=contoso,DC=local;0]

objectclass   : organizationalUnit
CanonicalName : contoso.local/web servers
gplink        : [LDAP://cn={BE864EFE-6C07-4A53-A9D8-7EB6EB36BE5A},cn=policies,cn=system,DC=contoso,DC=local;0]
```

```powershell
###List sites with linked GPOs
PS C:\> Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase "CN=Configuration,$((Get-ADDomain).DistinguishedName)" -Properties CanonicalName,gpLink | select objectclass,CanonicalName,gplink | Format-List

objectclass   : site
CanonicalName : contoso.local/Configuration/Sites/mysite
gplink        : [LDAP://cn={BE864EFE-6C07-4A53-A9D8-7EB6EB36BE5A},cn=policies,cn=system,DC=contoso,DC=local;0]
```

计算机可以通过检查它所属的OU对象和域对象来确定应用于自身的GPO。

例如，计算机对象位于 CN=mypc,OU=workstations,OU=computers,DC=domain,DC=com 中的机器将应用工作站和计算机OU以及domain.com域的GPO