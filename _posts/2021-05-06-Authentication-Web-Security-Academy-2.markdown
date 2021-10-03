---
layout: article
title: Authentication--Web Security Academy 2
mathjax: true
key: a00003	
cover: /bkgs/1.png
modify_date: 2021-08-6
show_author_profile: true
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

## 前言

这篇是Web Security Academy的Authentication部分

https://portswigger.net/web-security/sql-injection/cheat-sheet)

## 身份鉴定三因素

There are three authentication factors into which different types of authentication can be categorized:

- Something you **know**, such as a password

- Something you **have**, that is, a physical object like a mobile phone or security token

- Something you **are** or do, for example, your biometrics or patterns of behavior

  

## Vulnerabilities in password-based login

- ### Username enumeration

  you should pay particular attention to any differences in:

  **Status codes:like 200 302** 

  **Error messages**: any difference , even a ','

  **Response times**: set the password to a long long one ,check the response time.

  you can change X-Forwarded-For to change your ip (or Host to localhost)

- ### Flawed brute-force protection

- - #### **IP block**

  - - **change it**
    - **login  and logout** **，有些登陆进去后会重置失败次数**
    - **一次传多个密码？？？**

  - #### **account lock**

  - - **枚举，可能有些返回会不同？？？？**