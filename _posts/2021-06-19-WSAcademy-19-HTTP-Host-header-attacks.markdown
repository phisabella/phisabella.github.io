---
layout: article
title: WSAcademy 19 -- HTTP Host header attacks
mathjax: true
key: a00030
cover: /bkgs/1.png
modify_date: 2021-10-20
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- HTTP
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

这篇是Web Security Academy的HTTP Host header attacks部分<!--more-->

原文：[HTTP Host header attacks](https://portswigger.net/web-security/host-header)

## What is the HTTP Host header?

从HTTP/1.1开始，HTTP主机头是一个必需的请求头

它指定客户端要访问的域名，如：

```http
GET /web-security HTTP/1.1
Host: portswigger.net
```

## purpose

帮助确定客户端希望与哪个后端组件通信

如今，在同一IP地址上访问多个网站和应用程序是很常见的

当多个应用程序可通过同一IP地址访问时，这通常是以下情况之一的结果。

### Virtual hosting

一种可能的情况是，单个web服务器承载多个网站或应用程序

这已经不像以前那么普遍了，但在一些**基于云的SaaS解决方案**中仍然存在。

以这种方式在单个服务器上托管的网站称为“虚拟主机”。

### Routing traffic via an intermediary

另一种常见情况是，网站托管在不同的后端服务器上，但客户端和服务器之间的所有流量都通过中间系统路由

这种设置在客户端通过**内容交付网络（CDN,content delivery network）**访问网站的情况下尤其普遍。

## How does the HTTP Host header solve this problem?

当浏览器发送请求时，目标URL将解析为特定服务器的IP地址。

当此服务器接收到请求时，它**引用Host header来确定预期的后端**并相应地转发请求。

## What is an HTTP Host header attack?

如果服务器隐式信任Host header，并且**无法正确验证或转义它**，则攻击者可能会使用此输入注入操纵服务器端行为的有害payload

涉及将payload直接注入Host header的攻击通常称为“Host header injection”攻击。

现成的web应用程序通常不知道它们部署在哪个域上

例如，当他们需要知道当前域以生成电子邮件中包含的绝对URL时，他们可能会求助于从Host header检索域

```html
<a href="https://_SERVER['HOST']/support">Contact support</a>
```

header值也可用于网站基础设施的不同系统之间的各种交互。

Host header是利用一系列其他漏洞的潜在载体，尤其是：

- Web cache poisoning
- Business logic flaws in specific functionality
- Routing-based SSRF
- Classic server-side vulnerabilities, such as SQL injection

## How do HTTP Host header vulnerabilities arise?

由于存在错误的假设，即header不是用户可控制的

或者，可以通过注入其他header来覆盖Host

事实上，这些漏洞中的许多并不是因为编程不安全，而是因为相关基础设施中**一个或多个组件的配置不安全**。这些配置问题可能会发生是**因为网站将第三方技术集成到其架构中，而使用者并不必了解配置选项及其安全含义就能用**。

## How to test for vulnerabilities using the HTTP Host header

简而言之，您需要确定您是否能够修改 Host header ，并且仍然能够通过请求到达目标应用程序。如果是这样，您可以使用此header探测应用程序，并观察其对响应的影响。

### Supply an arbitrary Host header

有时，即使您提供了意外的Host header ，您仍然能够访问目标网站

例如，服务器有时会配置一个默认或回退选项，以防它们收到无法识别的域名请求

另一方面，由于Host header 是网站工作方式的基本组成部分，篡改它通常意味着您将无法访问目标应用程序。如果您的目标是**通过CDN**访问的，则这种情况尤其可能发生

### Check for flawed validation

请求可能会由于某种安全措施而被阻止，而不是收到“Invalid Host header”响应

例如，一些网站将**验证** Host header是否与**TLS握手中的SNI匹配**。

（**SNI，服务器名称指示**，TLS的扩展，用来解决一个服务器拥有多个域名的情况）

您应该尝试了解网站如何解析 Host header

例如，某些解析算法将从主机头中**省略端口**，这意味着**只验证域名**

```http
GET /example HTTP/1.1
Host: vulnerable-website.com:bad-stuff-here
Host: notvulnerable-website.com
Host: hacked-subdomain.vulnerable-website.com
```

### Send ambiguous requests

验证主机的代码和执行易受攻击操作的代码通常位于不同的应用程序组件中，甚至位于不同的服务器上

下面只是几个示例，说明如何创建不明确的请求。

#### Inject duplicate Host headers

偶尔会发现开发人员没有预料到这种情况，并暴露出一些有趣的行为quirks

两个头中的一个通常优先于另一个头，从而有效地覆盖其值

Consider the following request:：

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```

#### Supply an absolute URL

由于同时提供绝对URL和Host header 而导致的歧义也会导致不同系统之间的差异

您可以像复制主机头一样利用这些差异。

```http
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```

Note that you may also need to experiment with **different protocols**（HTTP/HTTPS）

#### Add line wrapping

您还可以通过使用空格字符缩进HTTP头来发现quirky behavior

```http
GET /example HTTP/1.1
 Host: bad-stuff-here      
Host: vulnerable-website.com
```

如果前端忽略缩进的header，则该请求将作为vulnerable-website.com的普通请求处理

#### Other techniques

https://portswigger.net/web-security/request-smuggling

### Inject host override headers

即使**不能使用不明确的请求覆盖主机头**，也可以通过**其他几个HTTP头**中的一个来注入负载，这些HTTP头的设计就是为了达到这个目的

有时，您可以使用`X-Forwarded-Host`注入恶意输入，同时绕过主机头本身的任何验证。

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```

尽管`X-Forwarded-Host`实际上是此行为的标准，但您可能会遇到其他具有类似用途的headers，包括：

- X-Host
- X-Forwarded-Server
- X-HTTP-Host-Override
- Forwarded

网站可能无意中支持这种行为，这通常是因为它们**使用的某些第三方技术**默认启用了其中一个或多个headers。