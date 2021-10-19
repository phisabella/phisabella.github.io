---
layout: article
title: WSAcademy 13 -- Clickjacking
mathjax: true
key: a00024
cover: /bkgs/1.png
modify_date: 2021-10-19
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- Clickjacking
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

这篇是Web Security Academy的Clickjacking部分<!--more-->

原文：[What is Clickjacking](https://portswigger.net/web-security/csrf)

## Clickjacking (UI redressing)

Clickjacking是一种基于界面的攻击，用户通过点击诱饵网站中的其他内容，被诱骗点击隐藏网站上的可操作内容

## How to construct a basic clickjacking attack

Clickjacking attacks use CSS to create and manipulate layers

## Clickjacking with prefilled form input

like：

```html
<iframe src="$url?email=hacker@attacker-website.com"></iframe>
```

## Frame busting scripts

通过web浏览器实施的常见客户端保护是使用框架破坏或框架破坏脚本。这些可以通过专有浏览器JavaScript附加组件或扩展（如**NoScript**）实现。

脚本通常经过精心编制，以执行以下部分或全部行为：

- 检查并确保当前应用程序窗口是主窗口或顶部窗口，

- 使所有框架可见，

- 防止点击不可见的框架

- 拦截并向用户标记潜在的点击劫持攻击。

一个有效的攻击者解决方案是使用HTML5 iframe `sandbox`属性。当使用 `allow-forms` or `allow-scripts` 值设置此选项，并且忽略了`allow-top-navigation`值时，then the  **frame buster script can be neutralized** ，因为iframe无法检查它是否为顶部窗口：

```html
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

## Combining clickjacking with a DOM XSS attack

当clickjacking被用作另一种攻击（如DOM XSS攻击）的载体时，它的真正威力就会显现出来

然后将XSS漏洞与iframe目标URL结合，以便用户单击按钮或链接，从而执行DOM XSS攻击。

## Multistep clickjacking

```html
<div class="firstClick">Test me first</div>
<div class="secondClick">Test me next</div>
<iframe src="$url"></iframe>
```

## How to prevent clickjacking attacks

点击劫持是一种浏览器端行为，其成功与否取决于浏览器功能以及是否符合现行的web标准和最佳实践

保护的实施取决于浏览器合规性和这些约束的实施。服务器端点击劫持保护的两种机制是**X-Frame-Options**和**Content Security Policy**。

### X-Frame-Options

header为网站所有者提供了对iFrame或对象使用的控制，因此可以使用`deny`指令禁止在框架中包含网页：

`X-Frame-Options: deny`

也可以限制到同源 as the website using the `sameorigin` directive

`X-Frame-Options: sameorigin`

or to a named website using the `allow-from` directive:

`X-Frame-Options: allow-from https://normal-website.com`

### Content Security Policy ([CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy))

csp是一种检测和预防机制，提供对XSS和点击劫持等攻击的缓解

`Content-Security-Policy: policy`

推荐的点击劫持保护是在应用程序的CSP中加入 `frame-ancestors`指令。`frame-ancestors 'none'`指令的行为与`X-frame-Options deny`指令类似。 `frame-ancestors 'self'`指令大致等同于X-frame-Options `sameorigin`指令。以下CSP仅将frames列为同一域的白名单：

`Content-Security-Policy: frame-ancestors 'self';`

也可以限制到指定网站

`Content-Security-Policy: frame-ancestors normal-website.com;`

为了有效对抗点击劫持和XSS，CSP需要仔细开发、实施和测试，并应作为多层防御策略的一部分使用。



（some content in XSS）

