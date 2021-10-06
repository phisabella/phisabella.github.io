---
layout: article
title: Comm Protocols+extras--AD from 0 to 0.9 part 8
mathjax: true
key: a00012
cover: /bkgs/3.jpg
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

这篇是AD from 0 to 0.9系列笔记的第八部分，主要是**Communication Protocols和[Microsoft extras](https://zer1t0.gitlab.io/posts/attacking_ad/#microsoft-extras)相关**<!--more-->

原文： [Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/#why-this-post) 

# **Communication Protocols**

You can check the [ports required by Windows services in the Microsoft docs](https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements).

## **SMB**

[SMB](https://en.wikipedia.org/wiki/Server_Message_Block#SMB_/_CIFS_/_SMB1) (Server Message Block)，是一种广泛用于AD（以及任何其他Windows网络）的协议，用于在计算机（通常是Windows）之间共享文件和通信

默认情况下，每台Windows计算机都允许使用SMB协议进行连接。最初，SMB通过NetBIOS（[datagram](https://zer1t0.gitlab.io/posts/attacking_ad/#netbios-datagram-service) and [session](https://zer1t0.gitlab.io/posts/attacking_ad/#netbios-session-service) services）工作，但现在它可以直接通过TCP使用。端口**445/TCP**

```
###SMB and related protocols/ports
                                 .--------
                                |
                                |
                              .---
                   .--NBSSN-->| 139
                   |          '---
         .-----.   |            |  Windows
         | SMB |>--|            |
         '-----'   |            |  machine
            |      |          .---
            |      '---TCP--->| 445
            |                 '---
            |                   |
            |                   |
            |                   '--------
     .------------.
     |            |
  .------.   .----------.
  | NTLM |   | Kerberos |
  '------'   '----------'
```

作为攻击者，了解SMB非常有用，因为SMB用于创建包含有价值信息的共享，并可用于从计算机中过滤信息。

### **Shares**

共享类似于计算机共享的文件夹，以便网络中的其他计算机/用户访问。可以用 [net view](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh875576(v=ws.11)) command, the [Get-SmbShare](https://docs.microsoft.com/en-us/powershell/module/smbshare/get-smbshare?view=windowsserver2019-ps) Powershell Cmdlet, or [smbclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py). 列出共享。

```powershell
###Shares of the domain DC
C:\> net view \\dc01.contoso.local /all
Shared resources at \\dc01.contoso.local

Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
ADMIN$      Disk           Remote Admin
C$          Disk           Default share
IPC$        IPC            Remote IPC
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```

访问其他计算机的共享的方式与访问本地计算机中的文件夹类似。可以使用UNC路径，如\\dc01.contoso.local\SYSVOL\或使用[net use](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/gg651155(v=ws.11)) 命令将远程共享映射到本地设备。

要在UNC路径中引用目标计算机，可以使用其dns名称或NetBIOS名称。例如，net view [\\dc01.contoso.local](file://dc01.contoso.local) or net view [\\dc01](file://dc01)

```powershell
###List folders inside a share
C:\> dir \\dc01\sysvol
 Volume in drive \\dc01\sysvol has no label.
 Volume Serial Number is 609D-528B

 Directory of \\dc01\sysvol

28/11/2020  11:02    <DIR>          .
28/11/2020  11:02    <DIR>          ..
28/11/2020  11:02    <JUNCTION>     contoso.local [C:\Windows\SYSVOL\domain]
               0 File(s)              0 bytes
               3 Dir(s)  20,050,214,912 bytes free
```

共享很方便，不需要特殊的程序或类似的东西，同样对攻击者来说也很方便

```powershell
###Creating a shared that can be accesed by everyone
net share Temp=C:\Temp /grant:everyone,FULL
```

#### **Default shares**

有些以$结尾的共享，这些共享是C$、ADMIN$和IPC$，默认情况下，它们存在于任何Windows计算机中

要访问C$和ADMIN$，您必须在目标计算机上具有管理员权限。通过这些共享（特别是C$），您可以检查所有计算机文件。实际上，这些共享被几个工具使用。例如，[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)使用ADMIN$部署负责执行给定命令的二进制文件。

IPC$ shared 是一个特殊的共享文件，用于创建 [named pipes](https://zer1t0.gitlab.io/posts/attacking_ad/#named-pipes)

####  **Default domain shares**

除了普通共享外，域控制器还在域中发布可供域中任何用户/计算机使用的SYSVOL和NETLOGON共享。它们用于存储域中所有计算机（至少是Windows计算机）需要访问的文件。

SYSVOL共享通常用于存储计算机用于读取域中部署的组策略的组策略模板。[Sometimes these policies contains passwords](https://adsecurity.org/?p=2288)。您可以使用 \\\ \<domain>\SYSVOL UNC路径访问SYSVOL共享

```powershell
###List SYSVOL folders
PS C:\> dir \\contoso.local\SYSVOL\contoso.local

    Directory: \\contoso.local\SYSVOL\contoso.local


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        19/04/2021     17:12                Policies
d-----        28/11/2020     10:02                scripts
```

\\\ \<domain>\\\\SYSVOL\\<domain>\scripts策略是NETLOGON共享的别名。NETLOGON共享用于存储需要为域中的计算机执行的登录脚本。

### **Named pipes**

IPC$共享不是目录，但用于创建 [named pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)，允许不同计算机的进程通过 [RPC](https://zer1t0.gitlab.io/posts/attacking_ad/#rpc)（Remote Procedure Calls，远程过程调用）等机制在它们之间进行交互。

命名管道可以看作是允许机器在它们之间进行通信的TCP端口，但在SMB协议内部。它们用于执行RPC调用，允许许多协议通过SMB进行通信。

通常，在RPC/SMB堆栈上工作的协议定义一个可用于与远程服务联系的已知命名管道（与TCP/UDP端口的想法相同）。例如，RPC使用 \pipe\netlogon命名管道来交换Netlogon 协议的消息

## **HTTP**

[HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)（Hypertext Transfer Protocol）除了web上，还常用于AD。

HTTP被存在于AD域中的许多其他应用程序协议用作传输协议，如 [WinRM](https://zer1t0.gitlab.io/posts/attacking_ad/#winrm) (and thus [Powershell Remoting](https://zer1t0.gitlab.io/posts/attacking_ad/#powershell-remoting)), [RPC](https://zer1t0.gitlab.io/posts/attacking_ad/#rpc) or [ADWS](https://zer1t0.gitlab.io/posts/attacking_ad/#adws) (Active Directory Web Services).

```
                                 .----------
                                 |
                               .---
                      .------->| 80 HTTP / WebDAV
                      |        '---
                      |          |
                      |          |
                      |        .---
                      |------->| 443 HTTPS / WebDAV / PSWA
                      |        '---
                      |          |
                      |          |
                      |        .---
                      |------->| 593 RPC over HTTP Endpoint Mapper
                      |        '---  
        .---------.   |          |
        | HTTP(S) |>--|          |
        '---------'   |        .---
             |        |------->| 5985 WinRM HTTP
             |        |        '---
             |        |          |
             |        |          |
             |        |        .---
             |        |------->| 5986 WinRM HTTPS
             |        |        '---
             |        |          |
             |        |          |
             |        |        .---
             |        '------->| 9389 ADWS (on DCs)
             |                 '---
             |                   |
             |                   '----------
      .-------------.
      |             |
  .------.     .----------.
  | NTLM |     | Kerberos |
  '------'     '----------'
```

为了与Active Directory完全集成，HTTP支持使用NTLM和Kerberos进行身份验证，意味着HTTP连接容易遭受 Kerberos Delegation or [NTLM Relay](https://en.hackndo.com/ntlm-relay/#what-can-be-relayed) attacks。

在NTLM中继的情况下，需要特别注意的是HTTP连接不需要签名，因此非常容易受到NTLM cross relay attacks。事实上，有许多攻击，如 [PrivExchange](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/) or some [Kerberos RBCD computer takeover](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#case-study-1-mssql-rcelpe)，它们依赖于从HTTP到LDAP的NTLM中继。如果能够使用具有NTLM身份验证的计算机域帐户强制计算机执行HTTP请求，那可以渗透计算机with a [little of Kerberos RBCD magic](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#case-study-2-windows-1020162019-lpe)。

与HTTP相关，在Windows计算机中，您可以安装 [IIS](https://www.iis.net/) web服务器，这是 [WebDAV](https://en.wikipedia.org/wiki/WebDAV) 或PSWA（Powershell web Access）等技术的基础，这些技术可以在/pswa 端点中启用

还能用 [pivotnacci ](https://github.com/blackarrowsec/pivotnacci)在装IIS时创建一个在HTTP上的SOCKS

## **RPC**

RPC（Remote Procedure Call，远程过程调用）是一种协议，允许来自不同机器的程序通过网络调用函数在它们之间进行通信。Microsoft开发了一个名为 [MSRPC](https://en.wikipedia.org/wiki/Microsoft_RPC)的RPC协议，它是[DCE/RPC](https://en.wikipedia.org/wiki/DCE/RPC)的一个修改版本，带有一些扩展（在 [RPCE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15)中定义）。

MSRPC可以使用不同[protocols for transport](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/472083a9-56f1-4d81-a208-d18aef68c101)，如：

- TCP，使用端口135作为 Endpoint Mapper ，使用端口49152到65535作为端点
- 通过使用命名管道进行SMB
- NetBIOS
- HTTP，使用端口593作为端点映射器，使用端口49152到65535作为端点

```
###RPC related protocols and ports
                                                 .---
             .----->----------->---------------->| 135 Endpoint Mapper
             |                                   '---
             |
             |                       .-------.   .---
             |----->------------.--->| NBSSN |-->| 139
             |                  |    '-------'   '---
             |                  ^
 .-----.     |      .-----.     |                .---
 | RPC |>----|----->| SMB |>----'--------------->| 445
 '-----'     |      '-----'                      '---
    |        |         |
    |        |         |        .------.         .---
    |        |----->---|------->| HTTP |>--.---->| 593 Endpoint Mapper
    |        |         |        '------'   |     '---
    |        |         |           |       v
    |        |         |           |       |     .---
    |        '----->---|------->---|-------'---->| 49152 - 65535
    |                  |           |             '---
    |                  |           |
    '-----------------.'-----------'
                      |
                .-----'-----.
                |           |
             .------.  .----------.
             | NTLM |  | Kerberos |
             '------'  '----------'
```

在域中，计算机经常使用MSRPC在它们之间进行通信。Windows计算机将MSRPC用于许多不同的任务，例如管理服务或读取其他计算机的注册表。

（RPC还广泛用于通过LRPC（Local RPC）或 [ALPC](https://www.youtube.com/watch?v=D-F5RxZ_yXc)（Advanced Local Procedure Call 高级本地过程调用）与本地计算机中的程序进行通信）

为了执行所有这些任务，Microsoft定义了几个MSRPC接口，这些接口定义了不同的功能，允许从远程程序查询/调用计算机的不同服务。

每个接口由UUID（Universally unique identifier 通用唯一标识符）标识，如 12345778-1234-ABCD-EF00-0123456789AB，每个接口使用不同的端点。几个接口具有预定义的端点，例如命名管道。例如， Service Control Manager（SCMR，服务控制管理器）使用 \PIPE\svcctl命名管道。

但是，对于其他接口，远程端点会发生更改，因此为了确定远程端点，RPC客户端必须联系 Endpoint Mapper（EPM，端点映射器）以从GUID解析远程端点。

根据接口的不同，可以使用不同的传输协议。您可以使用[rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) and [rpcmap.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcmap.py) 实用程序来发现可用于连接到远程计算机中给定服务的RPC端点（及其协议）。此外，您可以使用 [RpcView](https://www.rpcview.org/)在本地计算机中探索RPC端点

```bash
###List remote endpoints of LSAT interface
$ python rpcdump.py 'contoso.local/Han:Solo1234!@192.168.100.2' | grep LSAT -A 20 | grep -v ncalrpc
Protocol: [MS-LSAT]: Local Security Authority (Translation Methods) Remote 
Provider: lsasrv.dll 
UUID    : 12345778-1234-ABCD-EF00-0123456789AB v0.0 
Bindings: 
          ncacn_np:\\DC01[\pipe\lsass]
          ncacn_ip_tcp:192.168.100.2[49667]
          ncacn_http:192.168.100.2[49669]
          ncacn_np:\\DC01[\pipe\cb4e7232b43a99b8]
```

下面是一些最常用的接口的描述，可以了解使用RPC可以做什么。按照传输协议划分了接口，以便让您知道当机器的不同端口打开时可以完成什么。

### **RPC over SMB**

以下RPC接口/协议可（且通常）通过SMB使用：

**DHCPM**

[DHCPM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4) （DHCP Server Management）用于管理DHCP服务器的配置。

**RPRN**

[RPRN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) (Print System Remote)用于管理远程计算机的打印。您可以使用 [SpoolSample](https://github.com/leechristensen/SpoolSample) or [printerbug.py](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) 通过RPRN触发 [printer bug](https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory/41)。

**RRP**

RRP（Windows Remote Registry Protocol，Windows远程注册表协议）允许从远程计算机读取和修改注册表项。您可以使用 [reg](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg)（如果打印“未找到网络路径”错误，则需要在远程计算机中 [start the "Remote Registry" service](https://msfn.org/board/topic/151891-windows-reg-command-across-network/)）或 [reg.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/reg.py)（这将使用SRVS自动启动“Remote Registry”服务）来操作远程注册表。

**SAMR**

[SAMR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380)（SAM Remote）允许连接其他计算机的SAM（Security Account Manager，安全帐户管理器），以便管理用户和组。您还可以使用[samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py)获取有关机器本地用户的信息。

**SCMR**

[SCMR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)（SCM Remote）用于连接其他机器的 [SCM](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager)（Service Control Manager，服务控制管理器），以便管理服务。是[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)实用程序用于在远程计算机中执行命令的协议。

**SRVS**

通过 [SRVS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9)（Server Service Remote，服务器服务远程）可以连接到远程计算机，以便管理连接、会话、共享、文件和传输协议。您可以使用[netview.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/netview.py)枚举会话，也可以使用 [net view](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh875576(v=ws.11))枚举远程计算机中的共享。

**TSCH**

[TSCH](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931)（Task Scheduler Service Remote，远程任务计划程序服务）用于管理远程计算机中的任务。您可以使用 [atexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py), [at](https://docs.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/use-at-command-to-schedule-tasks) or [schtasks](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)创建远程任务。

**WKST**

[WKST](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/5bb08058-bc36-4d3c-abeb-b132228281b7)（Workstation Service Remote，远程工作站服务）用于管理/查询某些工作站设置，如主机名、操作系统版本、用户会话或计算机域。您可以将WKST与 [netview.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/netview.py)一起使用来枚举会话。

```
###RPC protocols that works over SMB
 .-------.
 | DHCPM |>----.
 '-------'     |
               |
  .------.     |
  | RPRN |>----|
  '------'     |
               |
  .------.     |                                          .--------
  | RRP  |>----|                                          |
  '------'     |                                          |
               |                                        .---
  .------.     |                             .--NBSSN-->| 139
  | SAMR |>----|                             |          '---
  '------'     |      .------.     .-----.   |            |  Windows
               |----->| RPC  |>--->| SMB |>--|            |
  .------.     |      '------'     '-----'   |            |  machine
  | SCMR |>----|                      |      |          .---
  '------'     |                      |      '---TCP--->| 445
               |                      |                 '---
  .------.     |                      |                   |
  | SRVS |>----|                      |                   |
  '------'     |                      |                   '--------
               |               .------------.
  .------.     |               |            |
  | TSCH |>----|            .------.   .----------.
  '------'     |            | NTLM |   | Kerberos |
               |            '------'   '----------'
  .------.     |
  | WKST |>----'
  '------'
```

此外，还有一些特定于在域中用于查询DC的RPC接口：

**BKRP**

[BKRP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp/90b08be4-5175-4177-b4ce-d920d797e3a8)（BackupKey Remote Protocol，备份密钥远程协议）用于在AD域中传输DPAPI密钥。您可以使用[mimikatz lsadump::backupkeys](https://www.coresecurity.com/core-labs/articles/reading-dpapi-encrypted-keys-mimikatz#_Toc64019558) or [dpapi.py backupkeys](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dpapi.py)从域控制器检索DPAPI 备份密钥。

**LSAD**

[LSAD](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc)（LSA Domain Policy）是LSA（Local Security Authority，本地安全机构）管理用户、域信任和其他与安全相关的内容的远程接口。与LSAT一起使用。

**LSAT**

[LSAT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/1ba21e6f-d8a9-462c-9153-4375f2020894)（LSA Translations Methods）允许将SID翻译为主体名称。与LSAD一起使用。可以使用[lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/a45f331360ce2abdb1c517a35a1c407725b0d761/examples/lookupsid.py)根据SID枚举用户。

**NRPC**

[NRPC](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f)（Netlogon Remote Protocol）在域中使用，允许计算机通过查询域控制器对用户进行身份验证。也在不同域的域控制器之间使用，以便使用NTLM对不同域的用户进行身份验证。此外，它还允许获取用户信息、域信任或域控制器列表等信息。可以使用 [nltest](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc731935(v=ws.11))（Netlogon测试）执行多个请求。[Zerologon](https://www.secura.com/blog/zero-logon) 漏洞用的就是这个协议。

```
###RPC protocols that works over SMB (Domain Controller)
  .------.                                                .----------
  | BKRP |>----.                                          |
  '------'     |                                          |
               |                                        .---
  .------.     |                             .--NBSSN-->| 139
  | LSAD |>----|                             |          '---
  '------'     |      .------.     .-----.   |            |    Domain
               |----->| RPC  |>--->| SMB |>--|            |  
  .------.     |      '------'     '-----'   |            |  Controller
  | LSAT |>----|                      |      |          .---
  '------'     |                      |      '---TCP--->| 445
               |                      |                 '---
  .------.     |                      |                   |
  | NRPC |>----'                      |                   |
  '------'                            |                   '----------
                               .------------.
                               |            |
                            .------.   .----------.
                            | NTLM |   | Kerberos |
                            '------'   '----------'
```

RPC protocols that works over SMB (Domain Controller)

### **RPC over TCP**

此外，有些RPC接口不能通过SMB使用，但您可以通过TCP直接使用它们：

**DRSR**

[DRSR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47) (Directory Replication Service Remote)是域控制器用于复制数据的协议。它还可用于具有足够权限的攻击者，通过使用 [mimikatz lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#dcsync) or [impacket secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)执行 [dcsync attack](https://adsecurity.org/?p=1729)来复制域用户凭据。

**DCOM**

[DCOM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0) (Distributed COM)用于与远程计算机的 [COM](https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model) (Component Object Model，组件对象模型)对象交互。COM对象非常有用，可以用于很多事情，比如执行命令，这些都可以通过使用 [dcomexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py)来完成。

**WMI**

WMI（Windows Management Instrumentation Remote，远程Windows管理规范）是构建在COM对象之上的 [CIM](https://en.wikipedia.org/wiki/Common_Information_Model_(computing))（Common Information Model，公共信息模型）的Microsoft实现，它允许从单个界面查询和操作Windows计算机的不同部分。非常通用，可与 [wmic](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic)、Powershell cmdlet（如 [Get-WmiObject](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) ）或impacket WMI脚本（如 [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)）一起使用。

**WCCE**

WCCE（Windows Client Certificate Enrollment Protocol，Windows客户端证书注册协议）是一个DCOM接口，允许用户在[ADCS](https://zer1t0.gitlab.io/posts/attacking_ad/#adcs)中请求证书和其他与CA相关的服务。它可以与[certreq](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1) or [Certify](https://github.com/GhostPack/Certify).一起使用。

```
###RPC protocols that works over TCP
                                                        .--------
        .-----------.                                   |
        | (DC) DRSR |>-------.                          |
        '-----------'        |     .------.            .---
                             |---->| RPC  |>--TCP--.-->| 135 (EPM)
 .-----.        .------.     |     '------'        |   '---
 | WMI |>--.--->| DCOM |>----'        |            |     |  Windows
 '-----'   |    '------'              |            |     |
           |                          |            |     |  machine
 .------.  |                          |            |   .---
 | WCCE |>-'                          |            '-->| 49152 - 65535
 '------'                             |                '---  
                                      |                  |
                                      |                  |
                                .------------.           '--------
                                |            |
                             .------.   .----------.
                             | NTLM |   | Kerberos |
                             '------'   '----------'
```

## WinRM

除了RPC之外，还可以使用WinRM（Windows Remote Management）在其他机器中通信和执行操作。WinRM是 [WS-Management](https://en.wikipedia.org/wiki/WS-Management) (Web Services-Management)规范的Microsoft实现，该规范定义了通过HTTP上的SOAP管理计算机的协议。

WinRM使用 [WSMAN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsman/70912fec-c815-44ef-97c7-fc7f2ec7cda5) and [WSMV](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/055dc36b-db2a-41ae-a47b-82cbfa0b4a92) 中定义的一些扩展来访问远程计算机中的CIM对象。这些CIM对象类似于对WMI对象的更新。您可以使用[CIM Cmdlets](https://devblogs.microsoft.com/powershell/introduction-to-cim-cmdlets/) such as [Get-CimInstance](https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-7.1)访问本地和远程计算机中的CIM对象。此外，还可以使用[winrs](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/winrs)通过使用WinRM在远程计算机中执行操作。

```powershell
###Use CIM to get info from a remote computer
PS C:\> Get-CimInstance CIM_OperatingSystem -ComputerName dc01 | Format-List


SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 17763
RegisteredUser  : Windows User
SerialNumber    : 00431-10000-00000-AA522
Version         : 10.0.17763
PSComputerName  : dc01
```

默认情况下，WinRM服务在端口5985上侦听HTTP连接，在端口5986上侦听HTTPS连接。默认情况下，使用HTTP，因为WinRM消息在顶层加密。但是，WinRM可以配置为分别 [use the regular HTTP ports](https://adamtheautomator.com/winrm-port/#h-setting-winrm-compatibility-ports) 80和443进行HTTP和HTTPS连接。

```
###WinRM protocol stack
                                                               .----------
                                                               |
                                                               |
 .--------------------------------.                          .---
 |             WinRM              |                 .--TCP-->| 5985 or 80
 |                                |                 |        '---
 | .-----.    .---------------.   |   .---------.   |          |  Windows
 | | CIM |--->| WS-Management |>--|-->| HTTP(S) |>--|          |  
 | '-----'    '---------------'   |   '---------'   |          |  Machine
 |                                |        |        |        .---
 '--------------------------------'        |        '--SSL-->| 5986 or 443
                                           |                 '---
                                           |                   |
                                           |                   |
                                           |                   '----------
                                    .-------------.
                                    |             |
                                .------.     .----------.
                                | NTLM |     | Kerberos |
                                '------'     '----------'
```

## **Powershell remoting**

管理系统的一个很好的实用工具是Powershell远程处理，它允许客户端在远程计算机上建立Powershell会话，并使用[Powershell](https://docs.microsoft.com/en-us/powershell/)执行各种任务。默认情况下， [since Windows Server 2012 R2](https://www.dtonias.com/enable-powershell-remoting-check-enabled/)，在Windows server版本中默认启用Powershell remoting。

```powershell
###Remote PowerShell session with cleartext credentials
PS C:\> $pw = ConvertTo-SecureString -AsPlainText -Force -String "Admin1234!"
PS C:\> $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist "contoso\Administrator",$pw
PS C:\> 
PS C:\> $session = New-PSSession -ComputerName dc01 -Credential $cred
PS C:\> Invoke-Command -Session $session -ScriptBlock {hostname}
dc01
PS C:\> Enter-PSSession -Session $session
[dc01]: PS C:\Users\Administrator\Documents>
```

最初，Powershell远程处理构建在 [WinRM](https://zer1t0.gitlab.io/posts/attacking_ad/#winrm)协议之上。但是，它预计将在Linux机器中使用，因此它还支持 [SSH](https://zer1t0.gitlab.io/posts/attacking_ad/#ssh) 作为传输协议。

（ [Powershell Web Access](https://practical365.com/powershell-web-access-just-how-practical-is-it) (PSWA) 开着的话还能通过浏览器使用Powershell ）

```
###Powershell remoting protocol stack
                                                         .----------
                                                         |
                         .-----.                       .---
             .---------->| SSH |>---------TCP--------->| 22
             |           '-----'                       '---
             |              |                            |
  .------.   |              |                            |
  | PSRP |>--|              |                          .---
  '------'   |              |                 .--TCP-->| 5985 or 80
             |              |                 |        '---
             |  .-------.   |   .---------.   |          |
             '->| WinRM |>--|-->| HTTP(S) |>--|          |  
                '-------'   |   '---------'   |          |
                            |        |        |        .---
                            |        |        '--SSL-->| 5986 or 443
                            |        |                 '---
                            |        |                   |
                            |        |                   |
                            |        |                   '----------
                            |   .----------.
                            |   |          |
                         .----------.   .------.
                         | Kerberos |   | NTLM |
                         '----------'   '------'
```

要用远程Powershell，可以用一些 [PSSession CmdLets to use to execute commands on remote machines](https://www.netspi.com/blog/technical/network-penetration-testing/powershell-remoting-cheatsheet/)，Linux也可以[install Powershell](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7.1) or using a tool like [evil-winrm](https://github.com/Hackplayers/evil-winrm).

除了对 [lateral movement](https://www.ired.team/offensive-security/lateral-movement/t1028-winrm-for-lateral-movement)（横向移动）有用之外，还可以使用[JEA endpoints](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.1)（仅在WinRM上可用）作为[persistence mechanism](https://www.labofapenetrationtester.com/2019/08/race.html)，但渗透时要注意，因为 [Powershell has many logging features](https://es.slideshare.net/nikhil_mittal/hacked-pray-that-the-attacker-used-powershell)

### **Trusted Hosts**

除了能够使用它之外，Powershell还要求在客户端中正确设置TrustedHost变量。

默认情况下，Powershell远程处理允许您使用Kerberos连接到域中的所有计算机。但是，如果要连接不同域的计算机，则需要将该IP添加到TrustedHost值（或者用*匹配所有）。在这种情况下，您必须在**客户端而不是服务器中配置TrustedHost**

```powershell
###Configure TrustedHost in client to allow connections to any machine
PS C:\> Set-Item wsman:localhost\client\TrustedHosts -Value * -Force
```

也可以从Linux计算机使用Powershell，但是似乎无法在Linux中设置TrustedHosts（或使用协商的类似操作），以便从Linux计算机连接到其他域中的Windows计算机

## **SSH**

SSH（Secure Shell）是一种广泛使用的协议，用于访问和管理Linux等Unix系统，但自2018年起，它也可用于Windows。即使它与Active Directory没有直接关系，通常部署在域中的许多Linux机器都可以通过SSH进行访问，因此您应该知道它是如何工作的以及可以使用它做什么。

默认情况下，SSH服务侦听端口22。

```
###SSH port
						.----
                       |
   .-----.           .---
   | SSH |>---TCP--->| 22
   '-----'           '---
      |                |
      |                '----
      |
      |
 .----------.
 | Kerberos |
 '----------'
```

SSH是一种非常通用的协议，允许用户在远程系统上获取shell、传输文件（使用[scp](https://linux.die.net/man/1/scp)实用程序）和建立SSH隧道。

它被Linux机器大量使用，如果您能够找到一些 [ssh keys](https://zer1t0.gitlab.io/posts/attacking_ad/#ssh-keys)或有效的用户凭据，您可以使用它在域计算机之间移动。

```text
###SSH session in db.contoso.local as foo user
$ ssh foo@db.contoso.local
foo@db.contoso.local's password: 
Linux db 4.19.0-14-amd64 #1 SMP Debian 4.19.171-2 (2021-01-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Apr 26 11:23:20 2021 from 192.168.122.1
foo@db:~$ hostname
id
```

此外，如果将目标计算机添加到域中，也可以使用[Kerberos](https://zer1t0.gitlab.io/posts/attacking_ad/#kerberos)。您可以通过启用 [GSSAPI](https://zer1t0.gitlab.io/posts/attacking_ad/#gss-api)身份验证（使用 -o GSSAPIAuthentication=yes）来使用Kerberos身份验证。

#### **SSH tunneling**

SSH隧道允许您将连接从本地机器端口转发到远程机器，反之亦然，因此它非常有用，可以绕过防火墙和网络分段在网络中进行支点。

SSH支持 [three types of port forwarding](https://www.howtogeek.com/168145/how-to-use-ssh-tunneling/)：

**Local Port Forwarding**

​	在这种情况下，您可以将本地端口映射到远程计算机可访问的端口。例如，如果远程计算机remote.contoso.local可以访问您的计算机无法访问的web.contoso.local:80中的网站，则可以将本地端口（例如8080）映射到web.contoso.local的端口80，并使用执行 ssh -L 8080:web.contoso.local:80 user@remote.contoso.local的SSH连接user@remote.contoso.local. 然后，您可以通过访问本地端口8080来访问远程网页。

```
###SSH Local Port Forwarding
              local                              remote                web
           .----------.                        .--------.            .-----
           |          |      SSH Tunnel        |        |            |
  o      .---        ---. ================== .---      ---.        .---
 /|\ --->| 8080 -> rand | >>----TCP-->>--->> | 22 -> rand |>-TCP-->| 80
 / \     '---        ---' ================== '---      ---'        '---
           |          |                        |        |            |
           '----------'                        '--------'            '-----
```

**Remote Port Forwarding**

​	远程端口转发与本地端口转发相反。在这种情况下，您可以使远程计算机可以访问您的计算机可以访问的端口。例如，如果您可以访问web.contoso.local:80中的网页，但远程计算机无法访问，则可以使用以下命令 ssh -R 8080:web.contoso.local:80 user@remote.contoso.local将远程计算机的8080端口映射到web.contoso.local的80端口. 这样，连接到远程机器的8080端口的用户就能够访问web服务器。

```
###SSH Remote Port Forwarding
 web                 local                           remote 
 ----.            .----------.                     .--------.
     |            |          |     SSH Tunnel      |        |    
    ---.        .---        ---. ==============  .---      ---.        o
    80 |<--TCP-<| rand <- rand | <<--<<-TCP--<<  | 22 <- 8080 | <---- /|\
    ---'        '---        ---' ==============  '---      ---'       / \
     |            |          |                     |        |
 ----'            '----------'                     '--------'
```

**Dynamic Port Forwarding**

​	最后，通过创建 [SOCKS](https://en.wikipedia.org/wiki/SOCKS)代理，动态端口转发允许您与远程计算机可访问的任何端口通信。指定SOCKS代理将侦听的本地端口，它将通过SSH将所有请求转发到远程计算机，然后转发到目标计算机：端口。例如，您可以使用以下命令在端口8080中设置SOCKS代理 ssh -D 8080 user@remote.contoso.local.

```
###SSH Dynamic Port Forwarding
                                                                         web
                                                                       .-----
                                                                       |
                  local                            remote            .---
               .----------.                      .--------.    .---->| 80
               |          |      SSH Tunnel      |        |    |     '---
             .---        ---. ================ .---      ---.  |       |
     web:80  |              | >---web:80---->> |  ---> rand |>-'       '-----
  o  ------->|              |                  |         ---'
 /|\         | 8080 -> rand |                  | 22       |
 / \ db:3306 |              |                  |         ---.            db
     ------->|              | >---db:3306--->> |  ---> rand |>-.       .-----
             '---        ---' ================ '---      ---'  |       |
               |          |                      |        |    |     .---
               '----------'                      '--------'    '---->| 3306
                                                                     '---
                                                                       |
                                                                       '-----
```

有时在SSH服务器中[TCP Forwarding is disabled](https://man.openbsd.org/sshd_config#AllowTcpForwarding)，从而阻止创建SSH隧道。在这些情况下，您可以使用 [SaSSHimi](https://github.com/TarlogicSecurity/SaSSHimi) 创建隧道。

## **RDP**

RDP（Remote Desktop Protocol）是允许您连接到提供图形用户界面的其他计算机的协议。在Windows环境中通常用于连接和管理远程计算机，因为默认情况下，Windows中包括RDP的客户端和服务器。

确认RDP开着与否可以确认 3389/TCP or 3389/UDP 是不是开着

```
                       .----
                       |
   .-----.           .---
   | RDP |---------->| 3389 TCP and UDP
   '-----'           '---
                       |
                       '----
```

但是，要访问该计算机，用户必须是Administrators or Remote Desktop Users本地组的成员。另外，要小心，因为Windows中只允许图形会话，所以通过RDP连接可能会注销其他用户。

除了远程管理机器之外，您还可以 [use RDP to create a SOCKS proxy](https://www.errno.fr/RDPTunneling.html)，该代理允许使用 [SocksOverRDP](https://github.com/nccgroup/SocksOverRDP) or [freerdp](https://www.freerdp.com/) with [rdp2tcp](https://github.com/V-E-O/rdp2tcp)一起使用远程机器在网络上进行转换。

您还应该记住，当机器通过RDP连接时，用户**凭据会通过网络发送**到目标机器（因为[CredSSP](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider) provider），因此通过RDP连接的用户很容易通过转储lsass进程内存来进行凭据调整

# Microsoft extras

Active Directory是网络生态系统中的核心部分，许多其他Microsoft产品将其用于/增强多种用途。本节包括一些Microsoft软件，攻击者在域中安装时应注意这些软件。

## **LAPS**

[LAPS](https://adsecurity.org/?p=3164) (Local Administrator Password Solution)是一个用于管理域计算机本地管理员密码的实用程序。LAPS将本地管理员密码随机化，以避免重复使用凭据，并定期对其进行更改。

为此，LAPS向域的计算机对象添加两个属性： ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime.

 ms-Mcs-AdmPwd 存储机器本地Administrator 密码，并且只有在明确授予该密码时才能看到该密码。如果您能够获得本地管理员密码，则可以使用管理员权限连接到计算机（使用NTLM身份验证）

 ms-Mcs-AdmPwdExpirationTime可由任何人读取（默认情况下），因此，为了识别LAPS管理的计算机，可以搜索包含该属性的计算机对象。

## **Exchange**

Exchange是由Microsoft开发的邮件服务器，可以安装在Windows服务器中并与AD集成。

安装Exchange后，将在域中创建 [several groups and ACEs](https://adsecurity.org/?p=4119)。

在 [February 2019 update](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-february-2019-quarterly-exchange-updates/ba-p/609061)事件之前，最相关的事情可能是 **Exchange Windows Permissions****组**在默认情况下拥有对域对象的WriteDacl权限。这意味着，在过时的安装中，此类组的成员可以编写ACE，将DS-Replication-Get-Changes and DS-Replication-Get-Changes-All 权限授予域中的任何用户，从而允许该帐户执行dcsync攻击，然后检索域用户凭据。

此外，所有Exchange服务器所属的 Exchange Trusted Subsystem 组是 Exchange Windows Permissions组的成员。因此，破坏任何Exchange服务器都可能使攻击者拥有破坏整个域的权限。

最著名的对Exchange权限的滥用可能是 [PrivExchange attack](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)，该攻击滥用 [vulnerability on Exchange servers](https://www.zerodayinitiative.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange)，该漏洞允许用户强制从Exchange服务器到另一台计算机的HTTP身份验证连接。然后，通过执行从HTTP到LDAP的NTLM中继攻击，Exchange服务器被强制为任意用户帐户授予DCsync权限。Microsoft还在 [February 2019 update](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-february-2019-quarterly-exchange-updates/ba-p/609061).中发布了此漏洞的修补程序。

此外， [Organization Admins group](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/) （也由Exchange添加）可以控制 Exchange Windows Permissions and Exchange Trusted Subsystem 成员。除此之外， Organization Admins是Exchange服务器中的本地管理员，因此作为此组的成员，还允许用户渗透整个域。

```
###Exchange groups and permissions
                                                               .--------.
                                                               | Object |
                                                .--WriteDacl-->| domain |
                                                |              '--------'
                                                |
                                                |
                                                |
                                 .-----------------------------.
                                 |            Group            |
                         .------>| Exchange Windows Permission |
                         |       '-----------------------------'
                         |                      ^
                         |                      |
            .-controls---|                    member
            |            |                      |
            |            |                      ^
            |            |       .----------------------------.
            |            |       |           Group            |
            |            '------>| Exchange Trusted Subsystem |
            ^                    '----------------------------'
 .---------------------.               ^                ^
 |        Group        |               |                |
 | Organization Admins |               |                |
 '---------------------'             member           member
            v                          |                |
            |                .---------|----------------|----------.
            |                |         |    Exchange    |          |
            |                |         |    Servers     |          |
            |                |         |                |          |
            |                |        .---.            .---.       |
            |                |       /   /|           /   /|       |
            |                |      .---. |          .---. |       |
            |                |      |   | '          |   | '       |
            |                |      |   |/           |   |/        |
            |                |      '---'            '---'         |
            |                |      exch1            exch2         |
            |                |        ^                ^           |
            |                '--------|----------------|-----------'
            |                         |                |
            |                         '----------------'
            |                                  |
            '----->>------admin of------>>-----'
```

## **SQL Server**

Microsoft SQL Server（MSSQL）是由Microsoft创建的数据库管理系统。它通常安装在Windows Server机器上，侦听TCP端口1433，许多web应用程序将其用作数据库。

SQL Server侦听TCP端口1433，可以使用域凭据连接到该端口，因为它使用[TDS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec)协议，该协议与NTLM和Kerberos身份验证兼容。

要与SQL server通信，可以使用[TDS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec) protocol directly over [TCP or using SMB](https://docs.microsoft.com/en-us/sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access?view=sql-server-ver15#BKMK_ssde)。在使用TCP的情况下，默认端口为1433，但也可能使用动态端口。

```
  .------.     .----------.
  | NTLM |     | Kerberos |
  '------'     '----------'
     |              |
     '------.-------'
            |
            |
     .------'------.        .------------
     |             |        |
     |          .-----.   .---
     |      .-->| SMB |-->| 445/TCP
     |      |   '-----'   '---
     |      |               |
     |      |               |
  .-----.   |             .---         SQL
  | TDS |---'-----TCP---->| 1433/TCP  
  '-----'                 '---        Server
                            |
                            |
  .------.                .---
  | SQLR |--------UDP---->| 1434/UDP
  '------'                '---
                            |
                            '------------
```

[dynamic port ](https://docs.microsoft.com/en-us/sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access?view=sql-server-ver15#BKMK_dynamic_ports)使用时会用随机的TCP端口，要允许远程客户端发现此端口，必须在UDP端口1434中启用SQL Server浏览器，等待 [SQLR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/1ea6e25f-bff9-4364-ba21-5dc449a601b7)（SQL Server解析）查询。用impacket  [mssqlinstance.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlinstance.py)来发现SQL server动态端口，然后可以使用诸如[HeidiSQL](https://www.heidisql.com/), [SQL Server Management Studio](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver15), or [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/)之类的SQL Server客户端连接到数据库。

```powershell
###Query to SQL Server Browser
$ mssqlinstance.py 192.168.100.19
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Instance 0
ServerName:SRV01
InstanceName:SQLEXPRESS
IsClustered:No
Version:15.0.2000.5
[*] Instance 1
ServerName:SRV01
InstanceName:MSSQLSERVER
IsClustered:No
Version:15.0.2000.5
tcp:50377
```

```powershell
###SQL query with a dynamic port
PS C:\> . .\PowerUpSQL.ps1
PS C:\> Get-SQLQuery -Query "Select @@version" -Instance "srv01,50377"

Column1
-------
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) ...
```

SQL服务器一个重要特性是可以通过 xp_cmdshell 命令执行命令

（在错配环境中，即便 [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15)命令被禁用，用户还是能 [enable it with the sp_configure directive](https://www.tarlogic.com/en/blog/red-team-tales-0x01/).）

此外， xp_dirtree 命令可用于访问网络文件（使用UNC路径）或通过使用域计算机帐户向其他计算机发出经过身份验证的请求，以便 [recollect NTLM hashes](https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478)以破解或执行 [NTLM relay](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#case-study-1-mssql-rcelpe)。

（SQL注入有点超纲了，可以查看 [NetSPI](https://sqlwiki.netspi.com/), [Pentest Monkey](http://pentestmonkey.net/category/cheat-sheet/sql-injection) or [PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet) cheat sheets.）

此外，对于攻击者来说，**SQL Server** **links**可能是一个非常有用的特性。SQL Server允许创建与其他数据源（如其他SQL数据库）的链接。

这些链接的有趣之处在于，即使它们是由管理员这样的特权用户创建的，它们也可以被任何用户使用，并允许以链接创建者的权限 [execute commands in remote machines](https://www.netspi.com/blog/technical/network-penetration-testing/how-to-hack-database-links-in-sql-server/) 

```
###Using a link created by dbadmin
                         .---.                             .---.
                        /   /|         SQL link           /   /|
   o                   .---. | ========================= .---. |
  /|\  ---unpriv---->  |   | '  ---------dbadmin------>  |   | '
  / \                  |   |/  ========================= |   |/ 
                       '---'                             '---'  
                        db1                               db2
```

此外，如果您喜欢通过SQL Server进行数据透视，还可以使用 [mssqlproxy](https://github.com/blackarrowsec/mssqlproxy)在SOCKS代理中进行转换。要了解更多滥用SQL Server的方法，您可以使用 [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL/)工具包，当然，您应该查看它的[wiki](https://github.com/NetSPI/PowerUpSQL/wiki)。