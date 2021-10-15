---
layout: article
title: WSAcademy 5 -- Business logic vulnerabilities
mathjax: true
key: a00016
cover: /bkgs/1.png
modify_date: 2021-10-15
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- Business logic
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

这篇是Web Security Academy的Business logic vulnerabilities部分<!--more-->

原文：[https://portswigger.net/web-security/logic-flaws](https://portswigger.net/web-security/os-command-injection)

# How do business logic vulnerabilities arise?

业务逻辑漏洞经常出现，因为设计和开发团队对用户将如何与应用程序交互做出了有缺陷的假设。在一个组件上工作的人可能会对另一个组件的工作方式做出有缺陷的假设，因此，无意中导致了严重的逻辑漏洞

# Examples 

## Excessive trust in client-side controls

一个有根本缺陷的假设是，用户只能通过提供的web界面与应用程序交互。这很危险，因为它导致进一步假设客户端验证将阻止用户提供恶意输入

## Failing to handle unconventional input

应用的逻辑的一个目的是将用户输入限制为符合业务规则的值。如果没有明确的逻辑来处理给定的案例，这可能会导致意外和潜在的可利用行为。

特别是一些边界输入，比如很大或很小的数字输入以及基于文本的字段的超长字符串。

甚至可以尝试意外的数据类型。通过观察应用程序的响应，一些应该思考的反应：

- 对数据是否有任何限制？

- 输入边界值会发生什么？

- 用户输入有没有任何转换或规范化？


lab：

- 整数溢出（32位2147483647）
- 负数

- 长字符串（长到足以更改邮件地址，如255限制，以欺骗应用程序）

## Making flawed assumptions about user behavior

One of the most common root causes of logic vulnerabilities is making flawed assumptions about user behavior

### Trusted users won't always remain trustworthy

一些应用程序错误地认为，在最初通过这些严格控制之后，用户及其数据可以**无限期地被信任**。可能导致后续控制力度减轻

### Users won't always supply mandatory input

一个误解是，用户总是为强制输入字段提供值。

浏览器可能会阻止普通用户在没有必要输入的情况下提交表单，但我们知道，攻击者可以在传输过程中**篡改参数**。这甚至扩展到**完全删除参数**。

### Users won't always follow the intended sequence

许多事务依赖于由一系列步骤组成的预定义工作流。web界面通常会引导用户完成此过程

但是，攻击者不一定会遵守此预定顺序

即使在相同的工作流程或功能中，对事件顺序进行假设也可能导致广泛的问题

黑客可以随意重新法宝，并以任意顺序与服务器进行任何交互

要识别这些类型的缺陷，应该以意料外的顺序提交请求

例如跳过某些步骤、多次访问单个步骤、返回到前面的步骤，等等。

请务必密切注意遇到的任何错误消息或调试信息

这些信息可能是有价值的信息披露来源，有助于微调攻击并了解有关后端行为的关键细节。

lab: don’t follow the usual workflow ,jump or just drop packages.

### Domain-specific flaws

在寻找逻辑缺陷时，网上商店的折扣功能是一个典型的攻击面

特别注意根据用户操作确定的标准调整价格或其他敏感值的任何情况

尝试了解应用程序使用什么算法进行这些调整，以及在什么时候进行这些调整

没有这个领域的知识就可能会忽略危险的行为，因为你根本没有意识到它潜在的连锁反应

lab1：alternate between the two codes

lab2：use discount and Gift cards to add money infinitely（macro）

### Providing an encryption oracle

当用户可控制的输入被加密，然后产生的密文以某种方式提供给用户时，可能会发生危险的情况。这种输入有时被称为“encryption oracle”。

攻击者可以使用此输入使用正确的算法和非对称密钥加密任意数据。

如果在提供反向解密功能的站点上有另一个用户可控制的输入，则此问题可能会更加复杂。这将使攻击者能够解密其他数据以识别预期的结构

lab：comment and use the same algorithm to decrypt ciphertext and delete base64 bits to make a admin cookie to be admin.

but why the solution says delete 23-character base64 bits to delete 23 text?

(搜了一下似乎也不是一一对应的，base64加密：设字符串长度为n ，长度为 ⌈n/3⌉*4  ⌈⌉ 代表上取整，所以是怎么回事emmmm)

# How to prevent business logic vulnerabilities

简言之，防止业务逻辑漏洞的关键在于：

○ 确保开发人员和测试人员了解应用程序所服务的领域

○ 避免对用户行为或应用程序其他部分的行为进行隐式假设

确保开发人员和测试人员都能够完全理解这些假设以及应用程序在不同场景中应该如何反应也很重要

○ 为所有事务和工作流维护清晰的设计文档和数据流，并记录每个阶段所做的任何假设。

○ 尽可能清楚地编写代码

○ 注意对使用每个组件的其他代码的任何引用

然而，正如前文所展示的，这些缺陷通常是**构建应用程序的初始阶段的错误实践**的结果