## Kubernetes

<img src="README.assets/flower.svg" alt="images/flower.svg" style="zoom: 25%;" />

传统部署时代->虚拟化部署时代->容器部署时代

<img src="README.assets/container_evolution.svg" alt="部署演进" style="zoom:50%;" />

### 功能特性：

- **服务发现和负载均衡**
  Kubernetes 可以使用 DNS 名称或自己的 IP 地址公开容器，如果到容器的流量很大，Kubernetes 可以负载均衡并分配网络流量，从而使部署稳定。

- **存储编排**
  Kubernetes 允许您自动挂载您选择的存储系统，例如本地存储、公共云提供商等。

- **自动部署和回滚**
  您可以使用 Kubernetes 描述已部署容器的所需状态，它可以以受控的速率将实际状态更改为所需状态。例如，您可以自动化 Kubernetes 来为您的部署创建新容器，删除现有容器并将它们的所有资源用于新容器。

- **自动二进制打包**
  Kubernetes 允许您指定每个容器所需 CPU 和内存（RAM）。当容器指定了资源请求时，Kubernetes 可以做出更好的决策来管理容器的资源。

- **自我修复**
  Kubernetes 重新启动失败的容器、替换容器、杀死不响应用户定义的运行状况检查的容器，并且在准备好服务之前不将其通告给客户端。

- **密钥与配置管理**
  Kubernetes 允许您存储和管理敏感信息，例如密码、OAuth 令牌和 ssh 密钥。您可以在不重建容器镜像的情况下部署和更新密钥和应用程序配置，也无需在堆栈配置中暴露密钥。

一个 Kubernetes 集群包含 集群由一组被称作节点的机器组成。这些节点上运行 Kubernetes 所管理的容器化应用。集群具有至少一个工作节点和至少一个主节点。

工作节点托管作为应用程序组件的 Pod 。主节点管理集群中的工作节点和 Pod 。多个主节点用于为集群提供故障转移和高可用性。

![Kubernetes 组件](README.assets/components-of-kubernetes.png)

#### Control Plane

apiserver：restful统一集群入口，交给etcd存储

etcd：键值数据库

scheduler：监视新创建为指定运行节点的Pod，调度决策

controller-manager：

​	节点控制器：故障通知响应

​	副本(Replication)控制器：维护副本Pod数量

​	端点控制器：填充端点对象(加入Service和Pod)

​	服务账户和令牌控制：新命名空间创建账户和API访问令牌

#### Node

kubelet：节点运行代理，保证容器运行在Pod中

kube-proxy：网络代理，维护节点的网络规则

### 核心概念

Pod：最小部署单元，一组容器的集合，一个Pod中容器共享网络

Controller：确保Pod副本数量，确保所有Node运行同一个Pod，一次性任务和定时任务

Service：定义一组Pod的访问规则

## 通过Kubeadm集群配置实例

### Kubeadm核心指令

```shell
# 创建一个 Master 节点
$ kubeadm init
# 将一个 Node 节点加入到当前集群中
$ kubeadm join <Master节点的IP和端口 >
```

### 虚拟机配置

采用Paralles Desktop安装CentOS Minimal系统

<img src="README.assets/image-20200918104047450.png" alt="image-20200918104047450" style="zoom:33%;" />

安装wget指令：

```shell
yum install wget
```

默认的网络设置是没有enable的，因此，在安装完之后需要开启的话，需要保证开启”Shared Network”, 同时再运行命令”/sbin/dhclient eth0”, 这样虚拟机就可以通过宿主网络来进行访问了。

为了长久性，修改配置

```shell
sudo vi /etc/sysconfig/network-scripts/ifcfg-eth0

# 将其中的ONBOOT改为yes
ONBOOT=yes
```

采用FinalShell进行SSH连接，配置三台服务器(一个Master，两个Node)

<img src="README.assets/image-20200918104400316.png" alt="image-20200918104400316" style="zoom:33%;" />

FinalShell可以实时查看CPU、网络等运行状态

<img src="README.assets/image-20200918104626178.png" alt="image-20200918104626178" style="zoom:33%;" />

### 环境配置

```shell
# 关闭防火墙
systemctl stop firewalld
systemctl disable firewalld

# 关闭selinux
sed -i 's/enforcing/disabled/' /etc/selinux/config  # 永久
setenforce 0  # 临时

# 关闭swap
swapoff -a  # 临时
sed -ri 's/.*swap.*/#&/' /etc/fstab    # 永久

# 根据规划设置主机名
hostnamectl set-hostname <hostname>

# 在master添加hosts 这里的名字和主机名对应
cat >> /etc/hosts << EOF
192.168.1.14 k8smaster
192.168.1.15 k8snode1
192.168.1.16 k8snode2
EOF

# 将桥接的IPv4流量传递到iptables的链
cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system  # 生效

# 时间同步
yum install ntpdate -y
ntpdate time.windows.com
```

### 节点安装Docker、kubeadm、kubelet

Kubernetes默认CRI(容器运行时)为Docker

1、Docker安装

2、注册阿里云镜像服务

3、添加阿里云yum软件源

```shell
$ cat > /etc/yum.repos.d/kubernetes.repo << EOF
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=0
repo_gpgcheck=0
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF
```

4、安装kubeadm、kubelet和kubectl

```shell
$ yum install -y kubelet-1.18.0 kubeadm-1.18.0 kubectl-1.18.0
$ systemctl enable kubelet
```

### 部署Master节点

```shell
$ kubeadm init \
  --apiserver-advertise-address=192.168.1.11 \
  --image-repository registry.aliyuncs.com/google_containers \
  --kubernetes-version v1.18.0 \
  --service-cidr=10.96.0.0/12 \
  --pod-network-cidr=10.244.0.0/16
```

使用kubectl工具

```shell
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
$ kubectl get nodes
```

### 部署Node节点

```shell
$ kubeadm join 192.168.1.11:6443 --token esce21.q6hetwm8si29qxwn \
    --discovery-token-ca-cert-hash sha256:00603a05805807501d7181c3d60b478788408cfe6cedefedb1f97569708be9c5

# 生成新的token
kubeadm token create --print-join-command
```

### 部署CNI网络插件

```shell
# 地址无法访问，添加IP地址
sudo vi /etc/hosts
199.232.28.133 raw.githubusercontent.com

# 部署插件
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
```

### 集群运行

<img src="README.assets/image-20200918100302952.png" alt="image-20200918100302952" style="zoom:33%;" />

Master组件：coredns、etcd、flannel-ds、apiserver、controller-manager、proxy、scheduler

Node组件：flannel-ds、proxy

### 测试kubernetes集群pod

```shell
# 新建一个nginx pod
$ kubectl create deployment nginx --image=nginx
$ kubectl expose deployment nginx --port=80 --type=NodePort
$ kubectl get pod,svc
```

<img src="README.assets/image-20200918101450417.png" alt="image-20200918101450417" style="zoom:33%;" />

可以看到pod已经在运行。根据ip地址加端口号访问，例：192.168.1.11:31557可看到访问结果：

<img src="README.assets/image-20200918102405643.png" alt="image-20200918102405643" style="zoom:33%;" />



## 通过二进制方式集群配置实例

### 配置三台虚拟机环境

<img src="README.assets/image-20200925100127003.png" alt="image-20200925100127003" style="zoom:50%;" />

初始化环境配置和adm方式相同。需要配置的环境如下：

| 角色       | IP           | 组件                                                         |
| ---------- | :----------- | ------------------------------------------------------------ |
| k8s-master | 192.168.1.14 | kube-apiserver，kube-controller-manager，kube-scheduler，etcd |
| k8s-node1  | 192.168.1.15 | kubelet，kube-proxy，docker，etcd                            |
| k8s-node2  | 192.168.1.16 | kubelet，kube-proxy，docker，etcd                            |

### 自签证书

为etcd和apiserver自签证书。CFSSL是开源证书管理工具，使用json文件生成证书。

#### 下载配置cfssl

 ```shell
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
chmod +x cfssl_linux-amd64 cfssljson_linux-amd64 cfssl-certinfo_linux-amd64
mv cfssl_linux-amd64 /usr/local/bin/cfssl
mv cfssljson_linux-amd64 /usr/local/bin/cfssljson
mv cfssl-certinfo_linux-amd64 /usr/local/bin/cfssl-certinfo
 ```

#### 自签证书颁发机构

```shell
#工作目录
mkdir -p ~/TLS/{etcd,k8s}
cd TLS/etcd
```

```shell
#自签CA
cat > ca-config.json<< EOF 
{ 
  "signing": { 
    "default": { 
    	"expiry": "87600h" 
     },
  "profiles": { 
    "www": { 
      "expiry": "87600h", 
      "usages": [ 
        "signing",
        "key encipherment", 
        "server auth", 
        "client auth" 
        ] 
      } 
    } 
  } 
}
EOF

cat > ca-csr.json<< EOF 
{ 
  "CN": "etcd CA", 
  "key": { 
    "algo": "rsa", 
    "size": 2048 
  },
  "names": [ 
    { 
    "C": "CN", 
    "L": "Beijing", 
    "ST": "Beijing" 
    } 
  ] 
}
EOF
```

```shell
#证书生成
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
```

```shell
#使用自签CA签发Etcd HTTPS证书
#证书申请文件：
cat > server-csr.json<< EOF
{
  "CN": "etcd",
  "hosts": ["192.168.1.14", "192.168.1.15", "192.168.1.16"],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [{
    "C": "CN",
    "L": "BeiJing",
    "ST": "BeiJing"
  }]
}
EOF
```

```shell
#生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=www server-csr.json | cfssljson -bare server
```

生成证书：

<img src="README.assets/image-20200925154047083.png" alt="image-20200925154047083" style="zoom:50%;" />

### 部署etcd集群

下载etcd：https://github.com/etcd-io/etcd/releases/tag/v3.4.13

```shell
#创建工作目录并解压二进制包
mkdir /opt/etcd/{bin,cfg,ssl} –p
tar zxvf etcd-v3.4.13-linux-amd64.tar.gz
mv etcd-v3.4.13-linux-amd64/{etcd,etcdctl} /opt/etcd/bin/
```

```shell
#etcd配置文件
cat > /opt/etcd/cfg/etcd.conf << EOF
#[Member]
#节点名称
ETCD_NAME="etcd-1"
#数据目录
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
#集群通信监听地址
ETCD_LISTEN_PEER_URLS="https://192.168.1.14:2380"
#客户端访问监听地址
ETCD_LISTEN_CLIENT_URLS="https://192.168.1.14:2379"
#[Clustering]
#集群通告地址
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://192.168.1.14:2380"
#客户端通告地址
ETCD_ADVERTISE_CLIENT_URLS="https://192.168.1.14:2379" 
#集群节点地址
ETCD_INITIAL_CLUSTER="etcd-1=https://192.168.1.14:2380,etcd-2=https://192.168.1.15:2380,etcd-3=https://192.168.1.16:2380" 
#集群token
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
#加入集群的当前状态，new新集群，existing已有集群
ETCD_INITIAL_CLUSTER_STATE="new"
EOF
```

```shell
#systemd管理etcd
cat > /usr/lib/systemd/system/etcd.service << EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
EnvironmentFile=/opt/etcd/cfg/etcd.conf
ExecStart=/opt/etcd/bin/etcd \
--cert-file=/opt/etcd/ssl/server.pem \
--key-file=/opt/etcd/ssl/server-key.pem \
--peer-cert-file=/opt/etcd/ssl/server.pem \
--peer-key-file=/opt/etcd/ssl/server-key.pem \
--trusted-ca-file=/opt/etcd/ssl/ca.pem \
--peer-trusted-ca-file=/opt/etcd/ssl/ca.pem \
--logger=zap
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
```

```shell
#拷贝证书
cp ~/TLS/etcd/ca*pem ~/TLS/etcd/server*pem /opt/etcd/ssl/
#设置开机启动
systemctl daemon-reload
systemctl start etcd
systemctl enable etcd
```

```shell
#将生成文件拷贝到其他节点
scp -r /opt/etcd/ root@192.168.1.15:/opt/
scp /usr/lib/systemd/system/etcd.service root@192.168.1.15:/usr/lib/systemd/system/
scp -r /opt/etcd/ root@192.168.1.16:/opt/
scp /usr/lib/systemd/system/etcd.service root@192.168.1.16:/usr/lib/systemd/system/

#分别修改其中的ETCD_NAME和地址为当前ip
vi /usr/lib/systemd/system/etcd.service
```

```shell
#查看集群部署状态
ETCDCTL_API=3 /opt/etcd/bin/etcdctl --cacert=/opt/etcd/ssl/ca.pem --cert=/opt/etcd/ssl/server.pem --key=/opt/etcd/ssl/server-key.pem --endpoints="https://192.168.1.14:2379,https://192.168.1.15:2379,https://192.168.1.16:2379" endpoint health
```

etcd集群已经部署成功

<img src="README.assets/image-20200925164342607.png" alt="image-20200925164342607" style="zoom:50%;" />

### 安装docker

```shell
#下载docker并配置
wget https://download.docker.com/linux/static/stable/x86_64/docker-19.03.9.tgz
tar zxvf docker-19.03.9.tgz
mv docker/* /usr/bin
```

```shell
#systemd管理docker
cat > /usr/lib/systemd/system/docker.service << EOF
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.service
Wants=network-online.target
[Service]
Type=notify
ExecStart=/usr/bin/dockerd
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TimeoutStartSec=0
Delegate=yes
KillMode=process
Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s
[Install]
WantedBy=multi-user.target
EOF
```

```shell
#创建配置文件
mkdir /etc/docker
cat > /etc/docker/daemon.json << EOF
{
  "registry-mirrors":["https://ach7yopc.mirror.aliyuncs.com"]
}
EOF

#开启docker
systemctl daemon-reload
systemctl start docker
systemctl enable docker
```



### 为apiserver自签证书

自签CA和etcd相同，配置相同。

```shell
#自签CA
cat > ca-config.json<< EOF 
{ 
  "signing": { 
    "default": { 
    	"expiry": "87600h" 
     },
  "profiles": { 
    "kubernetes": { 
      "expiry": "87600h", 
      "usages": [ 
        "signing",
        "key encipherment", 
        "server auth", 
        "client auth" 
        ] 
      } 
    } 
  } 
}
EOF

cat > ca-csr.json<< EOF 
{ 
  "CN": "kubernetes", 
  "key": { 
    "algo": "rsa", 
    "size": 2048 
  },
  "names": [ 
    { 
    "C": "CN", 
    "L": "Beijing", 
    "ST": "Beijing",
    "O": "k8s",
    "OU": "System"
    } 
  ] 
}
EOF
```

```shell
#证书生成
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
```

```shell
#使用自签CA签发kuber-apiserver https证书
cat > server-csr.json<< EOF
{
    "CN":"kubernetes",
    "hosts":[
        "10.0.0.1",
        "127.0.0.1",
        "192.168.1.14",
        "192.168.1.15",
        "192.168.1.16",
        "192.168.1.17",
        "192.168.1.18",
        "192.168.1.19",
        "192.168.1.20",
        "kubernetes",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster",
        "kubernetes.default.svc.cluster.local"
    ],
    "key":{
        "algo":"rsa",
        "size":2048
    },
    "names":[
        {
            "C":"CN",
            "L":"BeiJing",
            "ST":"BeiJing",
            "O":"k8s",
            "OU":"System"
        }
    ]
}
EOF
```

```shell
#生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes server-csr.json | cfssljson -bare server
```

### 部署master组件

下载地址：

https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.19.md#v1192

```shell
#解压 可执行文件apiserver scheduler controller-manager kubectl
mkdir -p /opt/kubernetes/{bin,cfg,ssl,logs}
tar zxvf kubernetes-server-linux-amd64.tar.gz
cd kubernetes/server/bin
cp kube-apiserver kube-scheduler kube-controller-manager /opt/kubernetes/bin
cp kubectl /usr/bin/
```

#### 部署apiserver

```shell
#apiserver配置文件
cat > /opt/kubernetes/cfg/kube-apiserver.conf << EOF
KUBE_APISERVER_OPTS="--logtostderr=false \\
#日志等级
--v=2 \\
#日志目录
--log-dir=/opt/kubernetes/logs \\
#etcd集群地址
--etcd-servers=https://192.168.1.14:2379,https://192.168.1.15:2379,https://192.168.1.16:2379 \\
#监听地址
--bind-address=192.168.1.14 \\
#https安全端口
--secure-port=6443 \\
#集群通告地址
--advertise-address=192.168.1.14 \\
#启用授权
--allow-privileged=true \\
#Service虚拟IP地址段
--service-cluster-ip-range=10.0.0.0/24 \\
#准入控制模块
--enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,ResourceQuota,NodeRestriction \\
#认证授权，启用RBAC授权和节点自管理
--authorization-mode=RBAC,Node \\
#启用TLS bootstrap机制
--enable-bootstrap-token-auth=true \\
#bootstrap token文件
--token-auth-file=/opt/kubernetes/cfg/token.csv \\
#Service nodeport类型默认分配端口范围
--service-node-port-range=30000-32767 \\
#apiserver访问kubelet客户端证书
--kubelet-client-certificate=/opt/kubernetes/ssl/server.pem \\
--kubelet-client-key=/opt/kubernetes/ssl/server-key.pem \\
#apiserver https证书
--tls-cert-file=/opt/kubernetes/ssl/server.pem \\
--tls-private-key-file=/opt/kubernetes/ssl/server-key.pem \\
--client-ca-file=/opt/kubernetes/ssl/ca.pem \\
--service-account-key-file=/opt/kubernetes/ssl/ca-key.pem \\
#连接etcd集群证书
--etcd-cafile=/opt/etcd/ssl/ca.pem \\
--etcd-certfile=/opt/etcd/ssl/server.pem \\
--etcd-keyfile=/opt/etcd/ssl/server-key.pem \\
#审计日志
--audit-log-maxage=30 \\
--audit-log-maxbackup=3 \\
--audit-log-maxsize=100 \\
--audit-log-path=/opt/kubernetes/logs/k8s-audit.log"
EOF
```

```shell
#将证书拷贝到配置路径
cp ~/TLS/k8s/ca*pem ~/TLS/k8s/server*pem /opt/kubernetes/ssl/
```

#### TLS Bootstraping

Master apiserver 启用 TLS 认证后，Node 节点 kubelet 和 kube-proxy 要与 kube-apiserver 进行通信，必须使用 CA 签发的有效证书才可以，当 Node 节点很多时，这种客户端证书颁发需要大量工作，同样也会增加集群扩展复杂度。为了简化流程，Kubernetes 引入了 TLS bootstraping 机制来自动颁发客户端证书，kubelet 会以一个低权限用户自动向 apiserver 申请证书，kubelet 的证书由 apiserver 动态签署。

```shell
#生成tocken
head -c 16 /dev/urandom | od -An -t x | tr -d ' '

#配置
cat > /opt/kubernetes/cfg/token.csv << EOF
38c9abdf7eea167c6526158f19475b2d,kubelet-bootstrap,10001,"system:node-bootstrapper"
EOF
```

```shell
#systemd管理apiserver
cat > /usr/lib/systemd/system/kube-apiserver.service << EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
[Service]
EnvironmentFile=/opt/kubernetes/cfg/kube-apiserver.conf
ExecStart=/opt/kubernetes/bin/kube-apiserver \$KUBE_APISERVER_OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
```

```shell
#启动kube-apiserver
systemctl daemon-reload
systemctl start kube-apiserver
systemctl enable kube-apiserver
```

```shell
#授权kubelet-bootstrap用户允许请求证书
kubectl create clusterrolebinding kubelet-bootstrap \
--clusterrole=system:node-bootstrapper \
--user=kubelet-bootstrap
```

#### 部署kube-controller-manager

```shell
cat > /opt/kubernetes/cfg/kube-controller-manager.conf << EOF
KUBE_CONTROLLER_MANAGER_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/opt/kubernetes/logs \\
--leader-elect=true \\
--master=127.0.0.1:8080 \\
--bind-address=127.0.0.1 \\
--allocate-node-cidrs=true \\
--cluster-cidr=10.244.0.0/16 \\
--service-cluster-ip-range=10.0.0.0/24 \\
--cluster-signing-cert-file=/opt/kubernetes/ssl/ca.pem \\
--cluster-signing-key-file=/opt/kubernetes/ssl/ca-key.pem \\
--root-ca-file=/opt/kubernetes/ssl/ca.pem \\
--service-account-private-key-file=/opt/kubernetes/ssl/ca-key.pem \\
--experimental-cluster-signing-duration=87600h0m0s"
EOF
```

```shell
#systemd管理controller-manager
cat > /usr/lib/systemd/system/kube-controller-manager.service << EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes
[Service]
EnvironmentFile=/opt/kubernetes/cfg/kube-controller-manager.conf
ExecStart=/opt/kubernetes/bin/kube-controller-manager \$KUBE_CONTROLLER_MANAGER_OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
```

```shell
systemctl daemon-reload
systemctl start kube-controller-manager
systemctl enable kube-controller-manager
```

#### 部署kube-scheduler

```shell
cat > /opt/kubernetes/cfg/kube-scheduler.conf << EOF
KUBE_SCHEDULER_OPTS="--logtostderr=false \
--v=2 \
--log-dir=/opt/kubernetes/logs \
--leader-elect \
--master=127.0.0.1:8080 \
--bind-address=127.0.0.1"
EOF
```

```shell
cat > /usr/lib/systemd/system/kube-scheduler.service << EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes
[Service]
EnvironmentFile=/opt/kubernetes/cfg/kube-scheduler.conf
ExecStart=/opt/kubernetes/bin/kube-scheduler \$KUBE_SCHEDULER_OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
```

```shell
systemctl daemon-reload
systemctl start kube-scheduler
systemctl enable kube-scheduler
```

部署完成后可以查看集群运行状态

```shell
kubectl get cs
```

<img src="README.assets/image-20200927193044304.png" alt="image-20200927193044304" style="zoom:50%;" />

### 部署node组件

在master节点下载的kubernetes中有kubelet和kube-proxy组件

![image-20201009140824560](README.assets/image-20201009140824560.png)

```shell
#工作目录 在master节点操作
mkdir -p /opt/kubernetes/{bin,cfg,ssl,logs}
cd kubernetes/server/bin
cp kubelet kube-proxy /opt/kubernetes/bin # 本地拷贝

# 拷贝到每个node节点
scp kubelet kube-proxy k8snode1:/opt/kubernetes/bin/
scp kubelet kube-proxy k8snode2:/opt/kubernetes/bin/
```

#### 部署kubelet

```shell
#配置文件
cat > /opt/kubernetes/cfg/kubelet.conf << EOF
KUBELET_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/opt/kubernetes/logs \\
#显示名称，集群中唯一
--hostname-override=k8smaster \\
#启用CNI插件
--network-plugin=cni \\
#用于连接apiserver
--kubeconfig=/opt/kubernetes/cfg/kubelet.kubeconfig \\
#首次启动向apiserver申请证书
--bootstrap-kubeconfig=/opt/kubernetes/cfg/bootstrap.kubeconfig \\
#配置参数文件
--config=/opt/kubernetes/cfg/kubelet-config.yml \\
#kubelet证书生成目录
--cert-dir=/opt/kubernetes/ssl \\
#管理Pod网络容器的镜像
--pod-infra-container-image=mirrorgooglecontainers/pause-amd64:3.0"
EOF
```

```yml
cat > /opt/kubernetes/cfg/kubelet-config.yml << EOF
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: 0.0.0.0
port: 10250
readOnlyPort: 10255
cgroupDriver: cgroupfs
clusterDNS:
- 10.0.0.2
clusterDomain: cluster.local 
failSwapOn: false
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: /opt/kubernetes/ssl/ca.pem 
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
evictionHard:
  imagefs.available: 15%
  memory.available: 100Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
maxOpenFiles: 1000000
maxPods: 110
EOF
```

```shell
# bootstrap.kubeconfig
KUBE_APISERVER="https://192.168.1.14:6443" # apiserver IP:PORT
TOKEN="38c9abdf7eea167c6526158f19475b2d" # 与token.csv里保持一致

cd /root/TLS/k8s

# 生成 kubelet bootstrap kubeconfig 配置文件
kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=bootstrap.kubeconfig
  
kubectl config set-credentials "kubelet-bootstrap" \
  --token=${TOKEN} \
  --kubeconfig=bootstrap.kubeconfig
  
kubectl config set-context default \
  --cluster=kubernetes \
  --user="kubelet-bootstrap" \
  --kubeconfig=bootstrap.kubeconfig
  
kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
```

```shell
#拷贝配置文件路径
cp /root/TLS/k8s/bootstrap.kubeconfig /opt/kubernetes/cfg
```

```shell
# systemd 管理 kubelet
cat > /usr/lib/systemd/system/kubelet.service << EOF
[Unit]
Description=Kubernetes Kubelet
After=docker.service
[Service]
EnvironmentFile=/opt/kubernetes/cfg/kubelet.conf
ExecStart=/opt/kubernetes/bin/kubelet \$KUBELET_OPTS
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
```

```shell
# 启动服务
systemctl daemon-reload
systemctl start kubelet
systemctl enable kubelet
```

批准kubelet证书申请并加入集群

```shell
# 查看kubelet证书请求
kubectl get csr
# 批准申请
kubectl certificate approve xxxxxxxxxxx
# 查看节点
kubectl get node
```

由于未部署网络插件，节点回没有准备就绪NotReady

<img src="README.assets/image-20201009145918479.png" alt="image-20201009145918479"  />

#### 部署kube-proxy

```shell
# 配置文件
cat > /opt/kubernetes/cfg/kube-proxy.conf << EOF
KUBE_PROXY_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/opt/kubernetes/logs \\
--config=/opt/kubernetes/cfg/kube-proxy-config.yml"
EOF
```

```yaml
# 配置yml
cat > /opt/kubernetes/cfg/kube-proxy-config.yml << EOF
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
metricsBindAddress: 0.0.0.0:10249
clientConnection:
	kubeconfig: /opt/kubernetes/cfg/kube-proxy.kubeconfig
hostnameOverride: k8smaster
clusterCIDR: 10.0.0.0/24
EOF
```

```shell
# 生成kube-proxy证书
# 切换工作目录
cd /usr/local/bin/k8s

# 创建证书请求文件
cat > kube-proxy-csr.json << EOF
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing",
      "ST": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF

# 生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy

ls kube-proxy*pem
# kube-proxy-key.pem  kube-proxy.pem
```

```shell
# kubeconfig文件
KUBE_APISERVER="https://192.168.1.14:6443"

cd /root/TLS/k8s

kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-proxy.kubeconfig
  
kubectl config set-credentials kube-proxy \
  --client-certificate=./kube-proxy.pem \
  --client-key=./kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig
  
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig
  
  
kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```

```shell
# 拷贝配置文件
cp /root/TLS/k8s/kube-proxy.kubeconfig /opt/kubernetes/cfg/
```

```shell
# systemd管理kube-proxy
cat > /usr/lib/systemd/system/kube-proxy.service << EOF
[Unit]
Description=Kubernetes Proxy
After=network.target
[Service]
EnvironmentFile=/opt/kubernetes/cfg/kube-proxy.conf
ExecStart=/opt/kubernetes/bin/kube-proxy \$KUBE_PROXY_OPTS
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
```

```shell
# 启动kube-proxy
systemctl daemon-reload
systemctl start kube-proxy
systemctl enable kube-proxy
```

#### 部署CNI网络

<img src="README.assets/image-20201012092553894.png" alt="image-20201012092553894" style="zoom:33%;" />

```shell
# https://github.com/containernetworking/plugins/releases/download/v0.8.6/cni-plugins-linux-amd64-v0.8.6.tgz
mkdir -p /opt/cni/bin
tar zxvf cni-plugins-linux-amd64-v0.8.6.tgz -C /opt/cni/bin

# 地址无法访问，添加IP地址
sudo vi /etc/hosts
199.232.28.133 raw.githubusercontent.com

wget https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
kubectl apply -f kube-flannel.yml

kubectl get pods -n kube-system
```

![image-20201009162031510](README.assets/image-20201009162031510.png)

授权apiserver访问kubelet

```shell
cat > apiserver-to-kubelet-rbac.yaml << EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:kube-apiserver-to-kubelet
rules:
  - apiGroups:
      - ""
    resources:
      - nodes/proxy
      - nodes/stats
      - nodes/log
      - nodes/spec
      - nodes/metrics
      - pods/log
    verbs:
      - "*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:kube-apiserver
  namespace: ""
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-apiserver-to-kubelet
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: kubernetes
EOF

kubectl apply -f apiserver-to-kubelet-rbac.yaml
```

```shell
# 增加新的Node节点
scp -r /opt/kubernetes k8snode2:/opt/
scp -r /usr/lib/systemd/system/{kubelet,kube-proxy}.service k8snode2:/usr/lib/systemd/system
scp -r /opt/cni/ k8snode2:/opt/
scp /opt/kubernetes/ssl/ca.pem k8snode2:/opt/kubernetes/ssl

# 证书申请审批后自动生成，删除重新生成
rm /opt/kubernetes/cfg/kubelet.kubeconfig 
rm -f /opt/kubernetes/ssl/kubelet*

# 修改主机名
vi /opt/kubernetes/cfg/kubelet.conf
--hostname-override=k8snode1
vi /opt/kubernetes/cfg/kube-proxy-config.yml
hostnameOverride: k8snode1
```

```shell
# 启动kubelet和kube-proxy
systemctl daemon-reload
systemctl start kubelet
systemctl enable kubelet
systemctl start kube-proxy
systemctl enable kube-proxy
```

在master批准node kubelet证书申请

```shell
kubectl get csr
kubectl certificate approve xxxxxxxxx
```

![image-20201009164852737](README.assets/image-20201009164852737.png)

查看Node状态，各个节点已正常运行中

![image-20201009175112902](README.assets/image-20201009175112902.png)

## 基本概念

### kubectl命令行工具

```shell
# 帮助
kubectl --help
# 创建pod例子
kubectl create deployment nginx --image=nginx
# 暴露端口
kubectl expose deployment nginx --port=80 --type=NodePort
# 查看端口信息
kubectl get pod,svc
# 查看组件状态
kubectl get cs
# 查看节点运行状态
kubectl get nodes
```

### yaml文件

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
      image: nginx:1.15
      port:
      - containerPort: 80
```

|    名称    | 内容       |    名称    | 美容       |
| :--------: | ---------- | :--------: | ---------- |
| apiversion | API版本    |    kind    | 资源类型   |
|  metadata  | 资源元数据 |    spec    | 资源规格   |
|  replicas  | 副本数量   |  selector  | 标签选择器 |
|  template  | Pod模板    |  metadata  | Pod元数据  |
|    spec    | Pod规格    | containers | 容器配置   |

#### create生成yaml文件

```shell
# 生成yaml文件
kubectl create deployment web --image=nginx -o yaml --dry-run > my1.yaml
```

#### get导出yaml文件

```shell
# 已部署好的项目
kubectl get deploy
# 导出yaml
kubectl get deploy nginx -o=yaml --export > my2.yaml
```

### Pod

多进程设计——最小部署单元，可包含多个容器(一组容器的集合)，一个pod中容器共享网络命名空间。

<img src="README.assets/image-20201010113017008.png" alt="image-20201010113017008" style="zoom:33%;" />

1、共享网络：通过Pause容器，把其他业务容器加入Pause容器中，同一个名称空间网络共享

2、共享存储：数据卷加载，持久化存储

<img src="README.assets/image-20201010112744244.png" alt="image-20201010112744244" style="zoom:33%;" />

#### Pod镜像拉取策略

```yaml
spec.containers[].imagePullPolicy: Always
     # IfNotPresent: 默认，镜像在宿主机不存在时才拉去
     # Always: 每次创建Pod都重新拉取
     # Never: Pod永远不会主动拉取这个镜像
```

#### Pod资源限制(由docker实现的)

```yaml
# 限制
spec.containers[].resources.limits.cpu: "500m" # 1核心=500m
spec.containers[].resources.limits.memory: "64Mi"
# 请求
spec.containers[].resources.requests.cpu
spec.containers[].resources.requests.memory
```

#### Pod重启策略

```yaml
# Always: 容器中只推出后，总是重启
# OnFailure: 容器异常退出（退出状态码非0）时重启
# Never: 终止退出从不重启
spec.restartPolicy: Never
```

#### Pod健康检查

```yaml
# 应用层面健康检查
# livenessProbe 存活检查 检查失败杀死容器，根据Pod的restartPolicy才做
# readinessProbe 就绪检查 检查失败将Pod从service endpoints中剔除
spec.containers[].livenessProbe:
  exec:
    command:
    - cat
    - /tmp/healthy
  imitialDelaySeconds: 5
  periodSecounds: 5

# Probe支持三种检查方法：
#    httpGet 发送请求，返回200-400为成功
#    exec 执行shell命令返回状态吗0为成功
#    tcpSocket 发起TCP Socket建立成功
```

#### Pod调度策略

<img src="README.assets/20190212152842_109.jpg" alt="clipboard.png" style="zoom:50%;" />

Pod创建过程：

	1. Createpod -- apiserver -- etcd
 	2. scheduler -- apiserver -- etcd -- 调度算法，把pod调度某个node节点上
 	3. node节点kubelet -- apiserver --读取etcd拿到分配给当前节点pod -- docker创建容器



##### 标签选择器nodeSelector

```shell
# 指定分组
kubectl label node k8snode1 env_role=dev
# 显示标签信息
kubectl get nodes k8snode1 --show-labels
```

```yaml
# 配置节点选择器
spec.nodeSelector.env_role: dev
```



##### 节点亲和性nodeAffinity

```yaml
spec:
  affinity:
    nodeAffinity:
      # 硬亲和性 必须满足约束条件
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions: # 必须满足env_role为dev或者test
          - key: env_role
            operator: In
            values:
            - dev
            - test
       # 软亲和性 不保证满足约束条件
       preferredDuringSchedulingIgnoredDuringExecution:
       - weight: 1 # 权重系数
         preference:
           matchExpressions: # 尝试满足，不保证绝对，若不存在依旧进行调度
           - key: group
             operator: In
             values:
             - otherprod
             
# 操作符 operator:
#		In 范围
#   NotIn 不在范围
#	  Exists 存在
#	  Gt 大于
#   Lt 小于
#	  DoesNotExists 不存在   
```



##### 污点和污点容忍Taint

nodeSelector和nodeAffinity为Pod属性，调度时实现。Taint节点不做普通分配调度，是节点的属性

场景：专用节点/配置特定硬件节点/基于Taint驱逐

污点：

```shell
# 查看节点污点情况
kubectl describe node k8smaster | grep Taint
#三个值：
#   NoSchedule: 一定不被调度
#   PreferNoSchedule: 尽量不被调度
#   NoExecute: 不会调度，并且驱逐Node已有Pod

# 为节点添加污点
kubectl taint node [node] key=value:污点值
# 删除污点
kubectl taint node [node] key=value:污点值-
```

污点容忍：（类似于软亲和性）

```yaml
spec:
  tolerations:
  - key: "env_role"
    operator: "Equal"
    value: "value"
    effect: "NoSchedule"
```



### Controller

#### Controller (Deployment)

在集群上管理和运行容器的对象，也叫做**工作负载**



##### Deployment 

应用场景：

​	部署无状态应用

​	管理Pod和ReplicaSet

​	部署、滚动升级等功能

​	应用场景：web服务、微服务

Pod和Controller通过**标签labels**建立联系，实现运维操作如伸缩、滚动升级等

![image-20201010163224750](README.assets/image-20201010163224750.png)

```shell
# 生成yaml文件
kubectl create deployment web --image=nginx --dry-run -o yaml > web.yaml
# 应用部署
kubectl apply -f web.yaml
kubectl get pods
# 生成暴露端口的yaml文件
kubectl expose deployment web --port=80 --type=NodePort --target-port=80 --name=web1 -o yaml > web1.yaml
# svc->service
kubectl get pod,svc
```

升级、回滚、弹性伸缩

```shell
# 将nginx升级到1.15版本
kubectl set image deployment web nginx=nginx:1.15
# 查看应用升级状态
kubectl rollout status deployment web
# 查看历史变化
kubectl rollout history deployment web
# 回滚
kubectl rollout undo deployment web
kubectl roolout undo deployment web --to-reversion=1
# 弹性伸缩(在线扩容)
kubectl scale deployment web --replicas=10
```



##### Service

定义一组Pod的访问规则，Service和Pod通过labels和selector标签建立关系。

1. 防止Pod失联（服务发现）
2. 定义一组Pod访问策略（负载均衡）

**常用类型**

​	ClusterIP：集群内部使用（默认）

​	NodePort：对外访问应用使用

​	LoadBalancer：对外访问，公有云

```shell
# 修改方式:
spec.type: NodePort

# 生成yaml文件
kubectl create deployment web --image=nginx --dry-run -o yaml > web.yaml
# 应用部署
kubectl apply -f web.yaml
# 端口暴露
kubectl expose deployment web --port=80 --target-port=80 --dry-run -o yaml > service.yaml
# apply
kubectl apply -f service.yaml

```



#### Controller (StatefulSet)

无状态：Pod相同，没有顺序要求，无需考虑在哪个node中运行，随意伸缩和扩展

有状态：每个pod独立，保持启动顺序和唯一性（唯一的网络标示符），持久存储，有序（例如mysql主从）

##### 部署有状态应用

无头service：ClusterIP : none

```yaml
apiVersion: v1
kind: Service #无头service
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  ports:
  - port: 80
    name: web
  clusterIP: None #None配置
  selector:
    app: nginx
---
apiVersion: apps/v1
kind: StatefulSet #有状态应用敷在管理控制器API
metadata:
  name: web-statefulset #名称
  namespace: default #名称空间
spec:
  serviceName: "nginx"
  replicas: 2
  selector:
     matchLabels:
       app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: docker.io/nginx
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: ["ReadWriteOnce"]
      volumeMode: Filesystem
      resources:
        requests:
          storage: 50Mi
      storageClassName: local-storage
```

Deployment和StatefulSet区别：有身份的（唯一标示）

​	根据主机名和一定规则生成域名：**主机名.service名称.名称空间.svc.cluster.local**

​	web-statefulset-0.web.default.svc.cluster.local



#### Controller (DaemonSet)

守护进程：确保node运行同一个pod

```yaml
kind: DaemonSet #守护
```

启动并进入守护进程：

```shell
# 部署守护进程
kubectl apply -f test.yml
# 进入pod之中
kubectl exec -it [Pod名] bash
```



#### Controller (Job)

job：一次性任务 / cronjob：定时任务

```yaml
apiVersion: batch/v1
kind: Job #一次性任务将结果logs打出
metadata:
  name: pi
spec:
  template:
    spec:
      containers:
      - name: pi
        image: perl
        command: ["perl", "-Mbignum=bpi", "-wle", "print bpi(2000)"]
      restartPolicy: Never
  backoffLimit: 4
```

查看任务执行情况

```shell
kubectl logs [服务名]
```

![image-20201019122228919](README.assets/image-20201019122228919.png)

执行后任务显示Completed

```shell
kubectl delete -f job.yaml
```



#### Controller (CronJob)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "*/1 * * * *" #cron表达式
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox
            args:
            - /bin/sh
            - -c
            - date; echo Hello from the Kubernetes cluster
          restartPolicy: OnFailure
```



### Secret

对数据进行加密，存储在etcd中，让pod容器以挂载volume的方式进行访问。

```shell
# 输出base64加密后的admin
echo -n 'admin' | base64
```

场景：凭证，base64编码

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  username: [加密后用户名]
  password: [加密后密码]
```

```shell
# 创建secret
kubectl create -f secret.yaml
```

#### 以变量形式挂载

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
  - name: nginx
    image: nginx
    env:
      - name: SECRET_USERNAME
        valueFrom:
          secretKeyRef: # 变量挂载
            name: mysecret
            key: username
      - name: SECRET_PASSWORD
        valueFrom:
          secretKeyRef:
            name: mysecret
            key: password
```

```shell
# 创建pod
kubectl apply -f secret-val.yaml
# 进入pod
kubectl exec -it mypod bash
# 输出变量
echo $SECRET_USERNAME
```

#### 以volume形式挂载

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
  - name: nginx
    image: nginx
    volumeMounts: #卷挂载
    - name: foo
      mountPath: "/etc/foo"
      readOnly: true
  volumes:
  - name: foo
    secret:
      secretName: mysecret
```

```shell
# 创建pod
kubectl apply -f secret-vol.yaml
# 进入容器
kubectl exec -it mypod bash
# 查看挂载的变量
cd /etc/foo
cat password
```



### ConfigMap配置管理

存储不加密数据到etcd中，pod以变量或数据卷挂载，多用于配置文件

```shell
# 创建configmap
kubectl create configmap redis-config --from-file=redis.properties
# 查看configmap
kubectl get cm
kubectl describe cm redis-config
```

#### volume挂载

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
  - name: busybox
    image: busybox
    command: ["/bin/sh", "-c", "cat /etc/config/redis.properties"]
    volumeMounts: #卷挂载
    - name: config-volume
      mountPath: /etc/config
  volumes:
  - name: config-volume
    configMap:  #configmap名称挂载
      name: redis-config
  restartPolicy: Never
```

```shell
# 查看日志
kubectl logs mypod
```

#### 变量挂载

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: myconfig
  namespace: default
data: #数据部分
  special.level: info
  special.type: hello
```

```shell
kubectl apply -f myconfig.yaml
kubectl get cm
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
  - name: busybox
    image: busybox
    command: ["/bin/sh", "-c", "echo $(LEVEL) $(TYPE)"]
    env:
      - name: LEVEL
        valueFrom:
          configMapKeyRef: #变量挂载
            name: myconfig
            key: special.level
      - name: TYPE
        valueFrom:
          configMapKeyRef:
            name: myconfig
            key: special.type
  restartPolicy: Never
```



### K8S集群安全机制

访问k8s集群时，需要经过三个步骤：

1. 认证
2. 鉴权（授权）
3. 准入控制

<img src="README.assets/1.png" alt="image.png" style="zoom: 67%;" />

均需要经过apiserver ---- 统一协调

**传输安全**：对外不暴露8080端口，只能内部访问。对外使用端口6443

**认证**：客户端认证常用方式：

​	https证书认证，基于ca证书

​	http token认证，通过token识别用户

​	http基本认证，用户名+密码

**鉴权**：基于RBAC（基于角色的访问控制）鉴权

**准入控制**：准入列表，存在则通过，否则拒绝。



#### RBAC

Role-Based Access Control  基于角色的访问控制

<img src="README.assets/1582958446712-2f30fb74-4b1c-4787-805b-d84186a40380.png" alt="image.png" style="zoom:50%;" />

**角色**：

​	role：特定命名空间访问

​	clusterrole：所有命名空间访问权限

**角色绑定**：

​	roleBinding：角色绑定到主体

​	clusterRoleBinding：集群角色绑定到主体

**RBAC实现鉴权**：

1. 创建命名空间并创建pod

```shell
# 创建命名空间
kubectl create ns roledemo
# 查看命名空间
kubectl get ns
# 在命名空间下创建pod
kubectl run nginx --image=nginx -n roledemo
```

2. 创建角色

```yaml
# 角色yaml
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: roledemo
  name: pod-reader
rules:
- apiGroups: [""] # ""表示core API group
  resources: ["pods"] # 仅对pods有操作权限
  verbs: ["get", "watch", "list"]
```

```shell
# 创建角色
kubectl apply -f rbac-role.yaml
kubectl get role -n roledemo
```

3. 创建角色与用户绑定

```yaml
# 用户yaml
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: read-pods
  namespace: roletest
subjects:
- kind: User
  name: lucy
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role # Role或者ClusterRole
  name: pod-reader #绑定的Role名字
  apiGroup: rbac.authorization.k8s.io
```

```shell
# 绑定用户与角色
kubectl apply -f rbac-rolebinding.yaml
# 获取绑定值
kubectl get role,rolebinding -n roledemo
```

4. 角色证书

```sh
# 和前述相同，生成证书文件
cat > lucy-csr.json<< EOF
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
# ......
```



### Ingress

原先方式：暴露端口，ip+端口号访问：使用Service中的NodePort类型，每个节点都会启动端口。

**Ingress作为统一入口**，由service关联一组pod

<img src="README.assets/image-20201021095748558.png" alt="image-20201021095748558" style="zoom: 40%;" />

1. **部署ingress Controller**

```shell
# 构建nginx应用
kubectl create deployment web --image=nginx
# expose暴露端口
kubectl expose deployment web --port=80 --target-port=80 --type=NodePort
```

**部署官方维护的ingress controller（nginx）**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---

kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-configuration
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---
kind: ConfigMap
apiVersion: v1
metadata:
  name: tcp-services
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---
kind: ConfigMap
apiVersion: v1
metadata:
  name: udp-services
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nginx-ingress-serviceaccount
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: nginx-ingress-clusterrole
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
rules:
  - apiGroups:
      - ""
    resources:
      - configmaps
      - endpoints
      - nodes
      - pods
      - secrets
    verbs:
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - nodes
    verbs:
      - get
  - apiGroups:
      - ""
    resources:
      - services
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - "extensions"
    resources:
      - ingresses
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
      - patch
  - apiGroups:
      - "extensions"
    resources:
      - ingresses/status
    verbs:
      - update

---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: Role
metadata:
  name: nginx-ingress-role
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
rules:
  - apiGroups:
      - ""
    resources:
      - configmaps
      - pods
      - secrets
      - namespaces
    verbs:
      - get
  - apiGroups:
      - ""
    resources:
      - configmaps
    resourceNames:
      # Defaults to "<election-id>-<ingress-class>"
      # Here: "<ingress-controller-leader>-<nginx>"
      # This has to be adapted if you change either parameter
      # when launching the nginx-ingress-controller.
      - "ingress-controller-leader-nginx"
    verbs:
      - get
      - update
  - apiGroups:
      - ""
    resources:
      - configmaps
    verbs:
      - create
  - apiGroups:
      - ""
    resources:
      - endpoints
    verbs:
      - get

---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: RoleBinding
metadata:
  name: nginx-ingress-role-nisa-binding
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: nginx-ingress-role
subjects:
  - kind: ServiceAccount
    name: nginx-ingress-serviceaccount
    namespace: ingress-nginx

---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: nginx-ingress-clusterrole-nisa-binding
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: nginx-ingress-clusterrole
subjects:
  - kind: ServiceAccount
    name: nginx-ingress-serviceaccount
    namespace: ingress-nginx

---

apiVersion: apps/v1
kind: DaemonSet 
metadata:
  name: nginx-ingress-controller
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: ingress-nginx
      app.kubernetes.io/part-of: ingress-nginx
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ingress-nginx
        app.kubernetes.io/part-of: ingress-nginx
      annotations:
        prometheus.io/port: "10254"
        prometheus.io/scrape: "true"
    spec:
      hostNetwork: true
      serviceAccountName: nginx-ingress-serviceaccount
      containers:
        - name: nginx-ingress-controller
          image: siriuszg/nginx-ingress-controller:0.20.0
          args:
            - /nginx-ingress-controller
            - --configmap=$(POD_NAMESPACE)/nginx-configuration
            - --tcp-services-configmap=$(POD_NAMESPACE)/tcp-services
            - --udp-services-configmap=$(POD_NAMESPACE)/udp-services
            - --publish-service=$(POD_NAMESPACE)/ingress-nginx
            - --annotations-prefix=nginx.ingress.kubernetes.io
          securityContext:
            allowPrivilegeEscalation: true
            capabilities:
              drop:
                - ALL
              add:
                - NET_BIND_SERVICE
            # www-data -> 33
            runAsUser: 33
          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          ports:
            - name: http
              containerPort: 80
            - name: https
              containerPort: 443
          livenessProbe:
            failureThreshold: 3
            httpGet:
              path: /healthz
              port: 10254
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 10
          readinessProbe:
            failureThreshold: 3
            httpGet:
              path: /healthz
              port: 10254
              scheme: HTTP
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 10

---
apiVersion: v1
kind: Service
metadata:
  name: ingress-nginx
  namespace: ingress-nginx
spec:
  #type: NodePort
  ports:
  - name: http
    port: 80
    targetPort: 80
    protocol: TCP
  - name: https
    port: 443
    targetPort: 443
    protocol: TCP
  selector:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
```

<img src="README.assets/image-20201021111104523.png" alt="image-20201021111104523" style="zoom:50%;" />

2. **创建ingress规则**

````yaml
apiVersion: networking.k8s.io/v1beta1
kind: Ingress # ingress规则
metadata:
  name: example-ingress
spec:
  rules: # 规则
  - host: example.ingredemo.com # 访问域名
    http:
      paths:
      - path: /
        backend:
          serviceName: web # 应用名称
          servicePort: 80  # 端口
````

采用v1版本：

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
spec:
  rules:
  - host: foo.bar.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web
            port:
              number: 80
```

<img src="README.assets/image-20201021144338729.png" alt="image-20201021144338729" style="zoom:50%;" />

在本机配置host文件：

```shell
sudo vi /etc/hosts
# 在host文件中加入
192.168.1.14	example.ingredemo.com
```

可直接通过域名访问：

<img src="README.assets/image-20201021145835896.png" alt="image-20201021145835896" style="zoom:50%;" />







## 参考

mac下Paralles配置CentOS网络：https://www.cnblogs.com/ghj1976/p/3746375.html

环境搭建1：https://www.cnblogs.com/liuyi778/p/12771259.html

环境搭建2：https://www.cnblogs.com/oscarli/p/12737409.html

CFSSL证书生成：https://blog.csdn.net/sujosu/article/details/101520260

K8S安全机制：https://www.cnblogs.com/benjamin77/p/12446780.html