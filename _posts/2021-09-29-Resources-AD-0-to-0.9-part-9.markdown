---
layout: article
title: Recommended resources--AD from 0 to 0.9 part 9
mathjax: true
key: a00013
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

这篇是AD from 0 to 0.9系列笔记的第九部分，主要是Recommended resources相关，之后应该也会加一些自己搜集整理的相关内容<!--more-->

原文： [Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/#why-this-post) 

# Recommended resources

文中有很多链接，都可以看看，有些关于AD信息的比较好的网站

- [Microsoft Windows      Technical Documents](https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-WINPROTLP/e36c976a-6263-42a8-b119-7a3cc41ddd2a)
- [Active Directory Security](https://adsecurity.org/)
- https://blog.harmj0y.net/
- [hackndo](https://en.hackndo.com/)
- https://dirkjanm.io/
- [Steve on Security](https://syfuhs.net/)
- [Lab of a Penetration Tester](https://www.labofapenetrationtester.com/)
- [ired.team](https://www.ired.team/)

 

还有很多工具，看它们的代码能学到很多AD机制和协议，以下列出的是很少一部分，文中还有更多

| [mimikatz](https://github.com/gentilkiwi/mimikatz)           | 可能是攻击Windows和Active       Directory最著名的工具。它在C中实现了从Windows计算机检索凭据和在Active Directory中模拟用户的 [all        kind of attacks](https://github.com/gentilkiwi/mimikatz/wiki) 。 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [impacket](https://github.com/SecureAuthCorp/impacket)       | impacket实现了这里用python描述的许多协议，了解它们的工作原理是值得的。它还包括许多实现此处描述的攻击的示例。 |
| [responder.py](https://github.com/lgandx/Responder)          | Responder 允许您滥用Windows解析协议执行大量PitM攻击，并为您提供大量收集NTLM哈希的协议服务器。值得知道它是如何工作的。 |
| [Rubeus](https://github.com/GhostPack/Rubeus)                | Rubeus是一个C#套件，用于从Windows计算机执行Kerberos攻击。您可以检查它以了解Kerberos的工作原理。 |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)  | CME是一个python工具，它允许您以一种简单的方式执行这里描述的许多不同的攻击。 |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound)     | BloodHound 允许你用许多不同的LDAP请求和其他请求来映射Active       Directory网络。如果您想了解Active Directory侦察，应该看看。 |
| [Powerview](https://github.com/BC-SECURITY/Empire/blob/master/data/module_source/situational_awareness/network/powerview.ps1) | 一个Powershell工具，它实现了许多Active Directory LDAP和其他协议查询，以从Active       Directory检索[all        kind of information](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)。 |
| [Empire](https://github.com/BC-SECURITY/Empire)              | 在Active Directory机器中部署代理的套件，允许您执行各种攻击。[data/module_source](https://github.com/BC-SECURITY/Empire/tree/master/data/module_source)目录包含许多工具，用于对Active       directory执行侦察和攻击，值得一看。 |



# 后记

这篇文章自己看了一遍，最近又整理了一遍，但还是有很多不太理解的地方，还得继续学习。这个系列的笔记就像作者说的一样当作索引就好，之后有遇到熟悉又陌生的内容再回来看看，有了新的发现再加一些自己的理解（毕竟到后面几篇更像翻译而不是笔记了hhh）。