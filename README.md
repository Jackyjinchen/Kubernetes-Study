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

​	服务账户和令牌控制：新命名空间床架账户和API访问令牌

#### Node

kubelet：节点运行代理，保证容器运行在Pod中

kube-proxy：网络代理，维护节点的网络规则

### 核心概念

Pod：最小部署单元，一组容器的集合，一个Pod中容器共享网络

Controller：确保Pod副本数量，确保所有Node运行同一个Pod，一次性任务和定时任务

Service：定义一组Pod的访问规则

## 集群配置实例

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
192.168.1.11 k8smaster
192.168.1.12 k8snode1
192.168.1.13 k8snode2
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

### 测试kubernetes集群pod

```shell
# 新建一个nginx pod
$ kubectl create deployment nginx --image=nginx
$ kubectl expose deployment nginx --port=80 --type=NodePort
$ kubectl get pod,sv
```

<img src="README.assets/image-20200918101450417.png" alt="image-20200918101450417" style="zoom:33%;" />

可以看到pod已经在运行。根据ip地址加端口号访问，例：192.168.1.11:31557可看到访问结果：

<img src="README.assets/image-20200918102405643.png" alt="image-20200918102405643" style="zoom:33%;" />

## 参考

mac下Paralles配置CentOS网络：https://www.cnblogs.com/ghj1976/p/3746375.html

环境搭建1：https://www.cnblogs.com/liuyi778/p/12771259.html

环境搭建2：https://www.cnblogs.com/oscarli/p/12737409.html