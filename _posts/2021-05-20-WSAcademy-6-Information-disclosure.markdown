---
layout: article
title: WSAcademy 6 -- Information disclosure
mathjax: true
key: a00017
cover: /bkgs/1.png
modify_date: 2021-10-15
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- Information disclosure
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

这篇是Web Security Academy的Information disclosure部分<!--more-->

原文：[Information disclosure vulnerabilities](https://portswigger.net/web-security/information-disclosure)

# What are some examples of information disclosure?

Some basic examples of information disclosure are as follows:

- robots.txt file or directory listing 找目录、结构这种
- 临时备份找源码（w ww.tar.zip这种）
- 错误信息找数据库、表这些
- 。。。。。。

# How to test for information disclosure vulnerabilities

## Fuzzing

- If you identify interesting parameters, you can try submitting unexpected data types and  specially crafted fuzz strings to see what effect this has

- You can also use the [Logger++](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81) extension except for burp intruder

## Using Burp Scanner

## Using Burp's engagement tools

You can access the engagement tools from the context menu - just right-click on any HTTP message, Burp Proxy entry, or item in the site map and go to "Engagement tools".

- Search

You can use this tool to look for any expression within the selected item

- Find comments

You can use this tool to quickly extract any developer comments found in the selected item

- Discover content

You can use this tool to identify additional content and functionality that is not linked from the website's visible content

## Engineering informative responses

正常测试工作流时看错误信息

# Common sources of information disclosure

## Files for web crawlers

Many websites provide files at **/robots.txt** and **/sitemap.xml** to help crawlers navigate their site

## Directory listings

目录列表本身不一定是安全漏洞。然而，如果网站也未能实施适当的访问控制，那么以这种方式泄露敏感资源的存在和位置显然是一个问题。

## Developer comments

有时，这些注释包含对攻击者有用的信息。例如，它们可能暗示存在隐藏目录，或者提供有关应用程序逻辑的线索。

## Error messages

One of the most common causes of information disclosure is verbose error messages

错误消息可以通过识别可利用的参数帮助您缩小攻击范围。使用的技术栈中间件这些也可能会有

## Debugging data

Debug messages can sometimes contain vital information for developing an attack, including:

- 可通过用户输入操作的关键会话变量的值

- 后端组件的主机名和凭据

- 服务器上的文件名和目录名

- 用于加密通过客户端传输的数据的密钥

## User account pages

- 一些网站存在逻辑缺陷，可能允许攻击者利用这些页面查看其他用户的数据。

- 攻击者可能无法完全加载其他用户的帐户页面，但获取和呈现用户注册电子邮件地址的逻辑（例如）可能不会检查用户参数是否与当前登录的用户匹配

- 当我们讨论访问控制和[IDOR](https://portswigger.net/web-security/access-control/idor) （Insecure direct object references）漏洞后面有详细讨论

## Source code disclosure via backup files

敏感数据有时甚至在源代码中硬编码。这方面的典型示例包括用于访问后端组件的API密钥和凭据。

有时甚至可能导致网站公开自己的源代码

示例：

- 当服务器处理具有特定扩展名的文件（如.php）时，它通常会执行代码，而不是简单地将其作为文本发送给客户端

- 文本编辑器通常在编辑原始文件时生成临时备份文件。这些临时文件通常以某种方式表示，例如在文件名后添加**波浪号（~）**或添加其他文件扩展名

- 一旦攻击者能够访问源代码，这将是识别和利用其他几乎不可能的漏洞的一大步。比如 [deserialization](https://portswigger.net/web-security/deserialization)。

## Information disclosure due to insecure configuration

由于配置不当，网站有时容易受到攻击，尤其是由于第三方技术的广泛使用

例如，HTTP的**TRACE**方法是为诊断目的而设计的。如果启用，web服务器将响应用**TRACE**方法的请求，即回显收到的请求

lab:

- get /admin ,notice that your request will be automatedly add an "X-Custom-IP-Authorization"
- proxy -> option ->"match and replace" ->add ->replace "X-Custom-IP-Authorization:     127.0.0.1"

![1](/pics/WSA/1.jpg)

## Version control history

默认情况下，Git项目将其所有版本控制数据存储在名为.Git的文件夹中

有时，网站会在生产环境中公开此目录。在本例中，您可能只需浏览到/.git即可访问它。

您可以使用本地安装的git打开.git，以访问网站的版本控制历史记录

lab：

- wget -r "https://acdb1fe81e11be3d809735de00b5002d.web-security-academy.net/.git"
- 回退：git revert -n  e022953cd9380051bb537517ba848f4a1d4dc138
- 显示版本间差别：git diff  e022953cd9380051bb537517ba848f4a1d4dc138  9b93ad368b8963c5dcc517d74326f0349d7234f7

# How do information disclosure vulnerabilities arise?

can broadly be categorized as follows:

- 没有从公共内容中删除内部内容。


例如，标记中的开发人员注释有时对生产环境中的用户可见。

- 网站和相关技术的不安全配置


例如，没禁用调试和诊断功能

- 应用程序的设计和行为有缺陷


例如，如果一个网站在不同的错误状态发生时返回不同的响应，这也会允许攻击者枚举敏感数据，例如有效的用户凭据

# How to prevent information disclosure vulnerabilities

- 确保参与制作网站的每个人都充分了解哪些信息是敏感信息。

- 作为QA或构建过程的一部分，审核任何潜在信息披露的代码

- 尽可能多地使用一般错误消息

- 再次检查是否在生产环境中禁用了任何调试或诊断功能。

- 确保完全了解所实施的任何第三方技术的配置设置和安全含义