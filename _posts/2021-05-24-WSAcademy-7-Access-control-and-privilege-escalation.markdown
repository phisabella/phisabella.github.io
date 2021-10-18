---
layout: article
title: WSAcademy 7 -- Access control and privilege escalation
mathjax: true
key: a00018
cover: /bkgs/1.png
modify_date: 2021-10-17
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- Access control
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

这篇是Web Security Academy的Access control vulnerabilities and privilege escalation部分<!--more-->

原文：[Access control vulnerabilities and privilege escalation](https://portswigger.net/web-security/information-disclosure)

# What is access control?

Access control (or **authorization**) is the application of constraints on who (or what) can perform attempted actions or access resources that they have requested

在web应用程序中，访问控制取决于身份验证和会话管理:

- **Authentication** identifies the user and confirms that **they are who they say they are**.
- **Session management** identifies which subsequent **HTTP requests are being made by that same user**.
- **Access control** determines **whether the user is allowed** to carry out the action that they are attempting to perform.

# Access control security models

访问控制安全模型是一组独立于技术或实现平台的访问控制规则的正式定义

## Programmatic access control

通过编程访问控制，用户权限矩阵**存储在数据库**或类似数据库中，访问控制通过编程方式参照该矩阵应用。这种访问控制方法可以包括角色、组或单个用户、流程集合或工作流，并且可以是高度细粒度的。

## Discretionary access control (DAC)（自主访问控制）

对资源或功能的访问受**用户或命名用户组**的限制

资源或功能的所有者可以向用户**分配或委派访问权限**

## Mandatory access control (MAC)

一种集中控制的访问控制系统，其中主体对某些对象（文件或其他资源）的访问受到限制

该模型通常与基于军事许可的系统相关联。

## Role-based access control (RBAC)

命名角色定义为其分配访问权限

然后将用户分配到单个或多个角色

当有足够多的角色来正确调用访问控制，但不会太多使得模型过于复杂和难以管理时，RBAC最为有效。

# access control categories

From a user perspective, access controls can be divided into the following categories:

## Vertical access controls

限制对**其他类型用户不可用**的敏感功能的访问。

通过垂直访问控制，不同类型的用户可以访问不同的应用程序功能

## Horizontal access controls

将对资源的访问限制为专门允许访问这些资源的用户。

通过水平访问控制，不同的用户可以访问**相同类型**的资源子集

## Context-dependent access controls

根据应用程序的状态或用户与应用程序的交互来限制对功能和资源的访问

它可以防止用户以**错误的顺序**执行操作

# Examples of broken access controls

## Vertical privilege escalation

如果用户可以访问他们不允许访问的功能，则这是垂直权限提升

### Unprotected functionality

在最基本的情况下，当应用程序不对敏感功能实施任何保护时，就会出现垂直权限提升

在某些情况下，敏感功能并没有得到强有力的保护，而是通过提供一个不太可预测的URL来隐藏：即所谓的**模糊安全性**

示例：URL可能在JavaScript中公开，该JavaScript基于用户角色构造用户界面：

### Parameter-based access control methods

某些应用程序在登录时确定用户的访问权限或角色，然后将此信息存储在用户可控制的位置，例如隐藏字段、cookie或预设查询字符串参数。

应用程序根据提交的值做出后续访问控制决策

### Broken access control resulting from platform misconfiguration

一些应用程序通过基于用户角色限制对特定URL和HTTP方法的访问，在平台层实施访问控制

例如，应用程序可能会配置如下规则：

*DENY: POST, /admin/deleteUser, managers*

一些应用程序框架支持各种非标准HTTP头，可用于覆盖原始请求中的URL，如**X-origing-URL**和**X-Rewrite-URL**，like：

```http
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
...
```

lab: Change the URL in the request line to / and add the HTTP header X-Original-URL: /admin
and do the same thing when deleting.

另一种攻击可能与请求中使用的HTTP方法有关

某些网站在执行操作时允许使用**其他HTTP请求方法**。

如果攻击者可以使用GET（或其他）方法对受限URL执行操作，那么他们可以绕过在平台层实现的访问控制。

lab:remember to change the cookie to your current account

## Horizontal privilege escalation

当一个用户能够访问属于另一个用户的资源而不是他们自己的资源时，就会出现横向权限提升

水平权限提升攻击可能使用与垂直权限提升类似的攻击方法



应用程序可以使用 **globally unique identifiers (GUIDs,全局唯一标识符)**来标识用户

GUIDs很难猜到，但是，属于其他用户的GUIDs可能会像用户消息或评论一样被公开。



在某些情况下，应用程序会检测用户何时不允许访问资源，并返回一个重定向到登录页面。

但是，包含重定向的响应可能仍然包含一些属于目标用户的敏感数据，因此仍能攻击。

### Horizontal to vertical privilege escalation

通常情况下，水平权限提升攻击可以转化为垂直权限提升攻击，这会损害更具权限的用户，如更改管理员的密码

### Insecure direct object references (IDOR) (不安全的直接对象引用)

IDOR是一种[访问控制](https://portswigger.net/web-security/access-control)应用程序使用用户提供的输入直接访问对象时出现的漏洞

IDOR漏洞通常与水平权限升级相关，但也可能与垂直权限升级相关

### Access control vulnerabilities in multi-step processes

example:

an attacker can gain unauthorized access to the function by skipping the first two steps and directly submitting the request for the third step with the required parameters.

### Referer-based access control

一些网站基于HTTP请求中提交的**Referer**标头进行访问控制

浏览器通常会将**Referer**头添加到请求中，以指示发起请求的页面。

### Location-based access control

一些网站根据用户的地理位置对资源实施访问控制

但它通常可以通过使用web代理、VPN或操纵客户端地理定位机制来规避。

# How to prevent access control vulnerabilities

通过采取纵深防御方法并应用以下原则：

○ 永远不要仅依靠模糊处理进行访问控制。

○ 除非资源打算公开访问，否则默认情况下拒绝访问。

○ 在可能的情况下，使用独立的应用程序范围的机制来实施访问控制。

○ 在代码级别，强制开发人员声明每个资源允许的访问权限，并默认拒绝访问。

○ 彻底审核和测试访问控制，确保其按设计工作。