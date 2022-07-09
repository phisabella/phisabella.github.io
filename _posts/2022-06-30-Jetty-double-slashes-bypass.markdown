---
layout: article
title: Jetty 双斜线绕过分析
mathjax: true
key: a00038
cover: /bkgs/3.jpg
modify_date: 2022-6-30
show_author_profile: true
excerpt_type: html
tag: 
- Java
- Jetty
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

因为工作需要研究了一下Jetty Filter绕过的问题，挺有意思

最近因为工作需要研究了一下Jetty Filter绕过的问题，挺有意思。开发者在使用组件的时候还是应该多少看下官方文档，多了解一下相关的特性。

<!--more-->

# 起因

使用Jetty 的 Filter在遇到类似 // 等URI的时候不会触发拦截，Filter被直接绕过,导致安全检查或业务逻辑被绕过，问题在于为什么能绕过，并且如何修复。这就需要研究一下Jetty相关文档以及其FIlter的匹配机制

# 官方处理

在10.0.5和11.0.5版本都加上了对//的限制，认为//是模糊请求的一种而返回400

![1](/pics/jetty/1.jpg)

由HttpUri处理//的情况

 ![2](/pics/jetty/2.jpg)

并且认为需要观望一段时间再将决定是否将这个feature添加到9，理由是，在之前处理类似情况的时候，修复一个bug反而会出现更多的bug

 ![3](/pics/jetty/3.jpg)

鉴于上述理由，以及官方已经停止对9的版本更新（安全问题和重大bug除外），不确定之后是否会加上这个feature

 ![4](/pics/jetty/4.jpg)

截止最新版本9.4.48.v20220622（is now at End of Community Support），还没有加入这个feature。

# 建议

1.在不更换组件的情况下建议使用通配符，或者单独拦截并丢弃包含“//”的请求来规避绕过问题，比如单独加上/*   的Filter，单独对URI做一次处理，但因为匹配机制设计的问题，不能排除之后有再次绕过的可能。

2.不能把鉴权全部放在Filter上，也不能因为前面有拦截就不在业务层做相应配置，建议采用纵深拦截处理并梳理业务逻辑，可以在业务代码里也加上相关的鉴权验证请求的有效性，如果没有经过Filter或者鉴权缺失则不进入业务流程。(参考https://4ra1n.love/post/bHi_S3YrB/ 加入Interceptor 在到达controller之前拦截)

3.升级到10.0.5/11.0.5及以上版本（需要Java11）

4.更换为Tomcat     （需要考虑Web服务器切换造成的兼容和性能问题）

# Jetty 匹配逻辑调试分析

## 测试结论

测试了Spring Boot默认集成的Jetty 9.4.42 和9.x最新版本9.4.48.v20220622，10.0.1-6，在10.0.5以前`//`， `/;/` 以及`/;{任意字符}/`（本质上还是`//`）可以绕过 ，10.0.5 以后加上了URI过滤，模糊请求会在进入Filter流程前就返回400 reason: Ambiguous empty segment in URI

这与Jetty自身开发特性有关，在FIlter没有设置为通配符*的情况下，比如/*，Jetty在Filter匹配上最终采用的是`String.equal()`函数，对字符串进行严格匹配，因此在过滤不严的情况下会产生绕过

同样的代码，如果把Jetty换成Tomcat就不会有上述问题 （似乎会单独对UrlPatterns做一次处理 参考： https://xz.aliyun.com/t/7244#toc-2 ，没有跟）

## 简单分析

经过调试发现，如果使用的不是通配符`*`，最终进行路由匹配的是`String.equal()`函数，会对字符串进行严格匹配，所以在url使用`//`能绕过，`/;/`在取path的时候会忽略";"，因此判断的时候还是`//`，经过简单测试，加上分号后，类似`/;'/`，`/;"/`,`/;~qdw1/`等也都能绕过，猜测在处理url的时候把分号及其后面的字符串都给丢弃了，url处理这块有时间可以再跟进一下。

![5](/pics/jetty/5.jpg)

## 调试流程

截图上使用的是Spring Boot默认集成的Jetty 9.4.42，目标url为"/hello"，Filter设置为"/hello",绕过url为"//hello"

注：

1.filter设置为/hello/*，传递//hello/spring的情况也是一样的

2.Jetty 9.4.48情况也几乎是一样的

### **//hello**

处理完请求后会到filter，加载所有filter

![6](/pics/jetty/6.jpg)

会先匹配 /hello 和 /*，应该是先匹配请求合法性，然后是自己写的filter，匹配//hello和/hello

9.4.48 filterMapping少了最后一个（4），会先匹配自己写的路由，不过不影响绕过结果

 ![7](/pics/jetty/7.jpg)

 

![8](/pics/jetty/8.jpg)

!pathSpec.equals(path) 判断字符串是否相等，这里如果不相等就进入*isPathWildcardMatch*(pathSpec, path)，字符串不相等，再进行通配符匹配

 ![9](/pics/jetty/9.jpg)

pathSpec.endsWith(**"/\*"**) 这里为false直接返回false

 ![10](/pics/jetty/10.jpg)

一路返回，结果//hello和设置的拦截器/hello没有匹配上，直接绕过

 ![11](/pics/jetty/11.jpg)

### /hello

match的 !pathSpec.equals(path)会返回false，即匹配成功

会返回true，构造一条不同的chain，进入到自己写的filter.doFilter()，拦截成功

 ![12](/pics/jetty/12.jpg)

Jetty在较老版本里会有一些别的绕过，参考 https://www.eclipse.org/jetty/security_reports.php

# 参考：

https://juejin.cn/post/6926710424142348302#heading-0

https://mvnrepository.com/artifact/org.eclipse.jetty/jetty-io

https://www.eclipse.org/jetty/security_reports.php





