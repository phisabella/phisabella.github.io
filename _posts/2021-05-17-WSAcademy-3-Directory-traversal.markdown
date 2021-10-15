---
layout: article
title: WSAcademy 3 -- Directory traversal
mathjax: true
key: a00014
cover: /bkgs/1.png
modify_date: 2021-10-15
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy 
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

这篇是Web Security Academy的Directory traversal部分<!--more-->

原文：[What is directory traversal, and how to prevent it? | Web Security Academy (portswigger.net)](https://portswigger.net/web-security/file-path-traversal)

# Reading arbitrary files via directory traversal

- **On Unix-based operating systems**

https://insecure-website.com/loadImage?filename=../../../etc/passwd

- **On Windows**, both ../ and ..\ are valid directory traversal sequences

[https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini](https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini)

# Common obstacles to exploiting file path traversal vulnerabilities

- 绝对路径, such as filename=/etc/passwd, to directly reference a file without using any traversal sequences.

- 嵌套路径, such as ....// or ....\/, which will revert to simple traversal sequences when the inner sequence is stripped.

- 用非标准的编码, such as ..%c0%af or ..%252f, to bypass the input filter.

  URL ： %252f => %2f  => /

  %c0%af 是非法的UTF-8表示形式

- 如果应用要求用户输入以固定基本目录开头, such as /var/www/images,就可能造成绕过. For example:

  filename=/var/www/images/../../../etc/passwd

- 如果要求用户输入是特定结尾, 如 .png, 就可用空字节在所需扩展名之前有效地终止文件路径（00截断）

  filename=../../../etc/passwd%00.png

# How to prevent a directory traversal attack

防止文件路径遍历漏洞的最有效方法是**避免将用户提供的输入**全部传递给文件系统API ，如果不能避免则有两种应对方式：

- 处理输入前先检查

  比如只允许输入字母数字字符

- 验证提供的输入后规范化路径

下面是一些简单Java代码的示例，用于根据用户输入验证文件的规范路径：File file = new File(BASE_DIRECTORY, userInput);

```java
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
  // process file
}
```

