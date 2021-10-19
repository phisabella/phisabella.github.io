---
layout: article
title: WSAcademy 11 -- CSRF
mathjax: true
key: a00022
cover: /bkgs/1.png
modify_date: 2021-10-19
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- CSRF
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

这篇是Web Security Academy的CSRF部分<!--more-->

原文：[What is CSRF (Cross-site request forgery)](https://portswigger.net/web-security/csrf)

# Cross-site request forgery (CSRF)

允许攻击者诱使用户执行他们不打算执行的操作，并部分绕过同源策略(same origin policy)

# How does CSRF work?

- **相关操作** 。攻击者有理由诱导的应用程序内的操作，例如修改其他用户的权限
- **基于Cookie的会话处理。**应用程序仅依赖会话Cookie来识别发出请求的用户
- **没有不可预测的请求参数**

# How to construct a CSRF attack

 CSRF PoC generator that is built in to Burp Suite Professional (hhhhhh)

# How to deliver a CSRF exploit

和反射XSS类似，Typically, the attacker will place the malicious HTML onto a web site that they control, and then induce victims to visit that web site.

like ：

```html
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">
```

# XSS vs CSRF

## What is the difference between XSS and CSRF?

XSS allows an attacker to execute **arbitrary JavaScript** within the browser of a victim user.

CSRF allows an attacker to induce a victim user to **perform actions** that they do not intend to.



XSS are generally more serious than CSRF:

- CSRF often only applies to a **subset** of actions that a user is able to perform

  XSS exploit can normally induce a user to perform **any** action that the user is able to perform

- CSRF can be described as a "**one-way**" vulnerability，cannot retrieve the response from that request。XSS is "**two-way**"

## Can CSRF tokens prevent XSS attacks?

- 反射XSS可以 . (However if the token be stolen or action performed by user , it won't work)
- 存储型XSS不行

# Preventing CSRF attacks

最可靠的方法是在相关请求中包含CSRF令牌：

- Unpredictable with high entropy，通常用于会话令牌。

- 绑定到用户的会话。

- 在执行相关行动之前，在任何情况下都要经过严格验证。

另一种对CSRF部分有效且可与CSRF令牌结合使用的防御措施是**SameSite cookies**。（限制第三方 Cookie，[SameSite ](http://www.ruanyifeng.com/blog/2019/09/cookie-samesite.html)）

## CSRF tokens

CSRF令牌是由服务器端应用程序生成并传输到客户端的唯一、秘密、不可预测的值，其传输方式使其包含在客户端发出的后续HTTP请求中。当发出后一个请求时，服务器端应用程序验证该请求是否包含预期的令牌，如果令牌丢失或无效，则拒绝该请求。

CSRF令牌可以防止CSRF攻击，因为攻击者不可能构造一个完全有效且合适的HTTP请求给受害者。

### How should CSRF tokens be generated?

使用加密强度伪随机数生成器（**PRNG**），该生成器在创建时带有时间戳和静态secret。

如果需要超出PRNG强度的进一步保证，您可以通过将其输出与某些特定于用户的熵连接起来生成单个令牌，并对整个结构进行强散列

### How should CSRF tokens be transmitted?

通常有效的方法是在使用**POST**方法提交的HTML表单的**隐藏字段**内将令牌传输给客户端

```html
<input type="hidden" name="csrf-token" value="CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz" />
```

CSRF标记应该**尽可能早地**放置在HTML文档中，最好放在任何非隐藏的输入字段之前，以及在HTML中嵌入用户可控制数据的任何位置之前

CSRF令牌**不应在cookie中传输**

### How should CSRF tokens be validated?

CSRF应该存储在用户会话数据的服务器端

无论请求的HTTP方法或内容类型如何，都必须执行验证。如果请求根本不包含任何令牌，则应以与存在无效令牌时相同的方式拒绝该请求。

## Defending against CSRF with SameSite cookies

`SameSite`属性可用于控制是否以及如何在跨站点请求中提交Cookie，这将**阻止向请求添加Cookie**，而不管它们来自何处。

当服务器发出Cookie时，`SameSite`属性被添加到`Set Cookie`响应头中，并且该属性可以被赋予两个值，`Strict`或`Lax`(还有None)。例如：

```
Set-Cookie: SessionId=sYMnfCUrAlmqVVZn9dqevxyFpKZt30NN; SameSite=Strict;
Set-Cookie: SessionId=sYMnfCUrAlmqVVZn9dqevxyFpKZt30NN; SameSite=Lax;
```

Strict，则浏览器不会将cookie包含在来自其他站点的任何请求中

Lax，则浏览器将在来自其他站点的请求中包含cookie，但前提是满足两个条件：

-  请求使用GET方法


- 该请求由**用户的顶级导航**（如单击链接）生成。其他请求，例如由**脚本发起的请求，将不包括cookie**。

两个重要的警告：

- 有些应用程序确实使用GET请求实现敏感操作。

- 许多应用程序和框架都能兼容不同的HTTP方法，它们可以切换POST和GET。

但是，与CSRF令牌一起使用时，SameSite Cookie可以提供额外的防御，以减轻基于令牌的防御中的任何缺陷。

# Common CSRF vulnerabilities

Most interesting CSRF vulnerabilities arise due to **mistakes made in the validation** of CSRF tokens.

## Validation of CSRF token depends on request method

某些应用程序在请求使用POST方法时正确验证令牌，但在使用**GET方法时会跳过验证**。

## Validation of CSRF token depends on token being present

有些应用有Token就验证，**没有Token则跳过**，可以直接移除整个Token参数

## CSRF token is not tied to the user session

某些应用程序不验证Token是否与发出请求的用户属于同一会话。相反，应用程序维护一个它已发布的Token的全局池，并接受该池中出现的任何Token。

## CSRF token is tied to a non-session cookie

在上述漏洞的一个变体中，某些应用程序确实将CSRF令牌绑定到cookie，但不绑定到用于跟踪会话的同一cookie。当应用程序使用两种不同的框架（一种用于会话处理，另一种用于CSRF保护）时，很容易发生这种情况，这两种框架未集成在一起：

如果网站包含允许攻击者在受害者浏览器中设置cookie的任何行为，则可能会被攻击。

攻击者可以使用自己的帐户登录到应用程序，获取有效令牌和关联cookie，利用cookie设置行为将其cookie放入受害者的浏览器，并在CSRF攻击中将其令牌提供给受害者。

```html
lab ：
/?search=test%0d%0aSet-Cookie:%20csrfKey=your-key

forge CSRF poc
Remove the script block, and instead add the following code to inject the cookie:
<img src="$cookie-injection-url" onerror="document.forms[0].submit()">
```

NOTE：

cookie设置行为甚至不需要与CSRF漏洞存在于同一web应用程序中。如果受控制的cookie具有合适的作用域，则可以利用**同一总体DNS域中的任何其他应用程序在目标应用程序中设置cookie**。例如，可以利用`staging.demo.normal-website.com`上的cookie设置功能来放置提交到`secure.normal-website.com`的cookie。

##  CSRF token is simply duplicated in a cookie

"double submit" defense against CSRF

- 在cookie和请求参数中复制每个令牌

- 应用程序只是验证请求参数中提交的令牌是否与cookie中提交的值匹配

- 易于实现，无需任何服务器端状态

Here, the attacker doesn't need to obtain a valid token of their own，he can forge one in the CSRF PoC.

# Referer-based defenses against CSRF

一些应用程序利用HTTP Referer标头试图防御CSRF攻击。通常通过验证请求**是否来自应用程序自己的域**来实现

这种方法通常不太有效，并且**经常会被绕过**。

（Referer标头包含链接到所请求资源的网页的URL）

## Validation of Referer depends on header being present

某些应用程序在请求中存在Referer头时验证该头，但如果忽略该头，则跳过验证。

有多种方法可以删除header，但最简单的方法是在承载CSRF攻击的HTML页面中使用META tag：

```html
<meta name="referrer" content="never">
```

## Validation of Referer can be circumvented

like:

如果应用程序验证Referer中的域以预期值开始，则攻击者可以改为**目标域的子域**：

```html
http://vulnerable-website.com.attacker-website.com/csrf-attack
```

如果应用程序只是验证Referer是否包含自己的域名，则攻击者可以将所需的值放在URL的其他位置：

```
http://attacker-website.com/csrf-attack?vulnerable-website.com
```

注:

默认情况下，许多浏览器现在会从`Referer`头中删除查询字符串。

您可以通过确保包含您的攻击的响应设置了`Referrer-Policy:unsafe-url` 头来覆盖此行为（请注意，在本例中`Referrer`拼写正确，以确保您注意！）。这将确保发送完整的URL，包括查询字符串。

```
lab:
history.pushState("", "", "/?your-lab-id.web-security-academy.net")
add "Referrer-Policy: unsafe-url" to header in exploit server
	
history.pushState(state, title, url)
```

请注意，与正常的Referer标题不同，“referrer”一词在这种情况下必须拼写正确。

