# https://blog.03k.org/post/mini-ppdns.html
# mini-ppdns 
专注于 DNS 故障转移的迷你DNS转发器。
`mini-ppdns` 是从`PaoPaoDNS`项目精简修改而来的纯粹转发器，致力于提供极致轻量化且高效的平滑 DNS 故障转移体验。
#### 快速启动

假设你的本地自建DNS是10.10.10.8，你的运营商DNS或者需要故障转移的DNS是223.5.5.5，
那么最简单的命令行启动：
```bash
mini-ppdns -dns 10.10.10.8 -fall 223.5.5.5
```
可以指定DNS端口和多个上游：
```bash
mini-ppdns -dns 10.10.10.8:53,10.10.10.9:53 -fall 223.5.5.5:53,119.29.29.29:53
```
#### 参数详解

- `-listen`可以指定监听地址和端口，默认是监听所有可监听的私有地址（跳过公网地址）：  
- `mini-ppdns -dns 10.10.10.8 -fall 223.5.5.5 -listen 127.0.0.1:53`  
- `-aaaa`可以指定是否开启IPv6的aaaa记录（默认为no，屏蔽aaaa）：  
`mini-ppdns -dns 10.10.10.8 -fall 223.5.5.5 -aaaa=yes`  
- `-force_fall`可以指定某些IP段总是走运营商/故障转移的DNS：  
`mini-ppdns -dns 10.10.10.8 -fall 223.5.5.5 -force_fall=192.168.1.10,192.168.2.0/24`  
- `-qtime`可以指定故障转移的延迟阈值（默认为250ms，一般不需要调整）:  
`mini-ppdns -dns 10.10.10.8 -fall 223.5.5.5 -qtime=250`  
- `-debug`输出详细的调试日志。  
- `-d`可以在后台运行。  
- `-config`可以指定加载配置文件，可以配置`mini-ppdns.ini`如下：
```ini
# 本地搭建的主DNS
[dns]
10.10.10.8:53
10.10.10.9:53

# 故障转移备用/运营商DNS
[fall]
223.5.5.5:53
119.29.29.29:53

# 监听地址端口
[listen]
127.0.0.1:53
192.168.1.1:53

[force_fall]
# 支持以下三种写法：单个 IP、CIDR 端、以及特定的 IP Range
# FakeIP场景可以利用这个功能，间接实现某些设备不走代理
192.168.1.10
192.168.2.0/24
192.168.3.2-192.168.3.100

[adv]
# 转移延迟阈值（毫秒）
qtime=250
# 是否开启 IPv6 查询解析（yes/no）
aaaa=no
```

---
# 在openwrt路由器上部署
在openwrt上部署说起来简单也复杂，因为很多openwrt里面有各种神神秘秘的插件互相干扰。其中不少会劫持DNS，此处部署过程仅包含一些常见的坑和注意事项。当然部分过程也适用于其他linux系统。  
- 去[release](https://github.com/kkkgo/mini-ppdns/tree/main/release)下载适合你的硬件架构的二进制文件。如果不清楚自己的硬件是什么架构，可以在终端输入`uname -m`。其中release名字带UPX的是为了给一些储存空间紧张的设备用的，如果你的设备空间充足下正常版本即可。
- 把`mini-ppdns`上传到你的设备，为了方便你可以上传到`/usr/sbin/mini-ppdns`,加执行权限`chmod +x /usr/sbin/mini-ppdns`。将你的配置文件储存在`/etc/mini-ppdns.ini`，然后执行`mini-ppdns -config /etc/mini-ppdns.ini`看看是否输出正常（比如提示某个端口已经被监听）。
- 添加自启动脚本。在openwrt上最简单的是编辑 `/etc/rc.local`，在 `exit 0` 之前添加你的启动命令，带上 `-d` 参数，程序会自动到后台，不会阻塞启动。当你修改了局域网的IP段或者配置，你需要重新启动`mini-ppdns`。

```bash
/usr/sbin/mini-ppdns -config /etc/mini-ppdns.ini -d
exit 0
```
或者写一个守护脚本加计划任务或者修改服务，此处提供了一个参考脚本：
https://github.com/kkkgo/mini-ppdns/blob/main/mini-ppdns.sh  
使用方法，把脚本上传到`/usr/sbin`加执行权限，`crontab -e`编辑计划任务：`* * * * * /usr/sbin/mini-ppdns.sh`即可。脚本启动之前检测是否已经存在mini-ppdns进程，如果存在就直接退出，因此可以直接让计划任务每分钟执行来作为守护。执行`mini-ppdns.sh restart`可以重载配置。
- 普通linux到这里已经弄完了，但一些linux安装过程中会自带DNS服务器导致占用监听端口，比如Ubuntu，可以禁用自带的DNS解析器：
```
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
#禁用后记得手动编辑/etc/resolv.conf手动写入DNS服务器
```
当然，openwrt自带dnsmasq，我们需要把他停用。
编辑 `/etc/dnsmasq.conf` 或在 OpenWrt 管理界面 (网络 -> DHCP/DNS -> 高级设置) 中：
```conf
# 将 DNS 端口设置为 0，彻底禁用 dnsmasq 的 DNS 解析功能（仅保留 DHCP 功能）
port=0
```
- 某些dnsmasq的禁用DNS解析会导致DHCP不下发DNS。所以我们还需要手动下发路由器的DNS。  
点击`网络-接口-LAN-DHCP服务器-高级设置`，在DHCP选项里面，手动设置DHCP的附加选项。下发DNS的选项是6，比如你的路由器IP是10.10.10.1，那么填入`6,10.10.10.1`。当然，在FakeIP场景下，你也可以顺便填入[option 121](https://github.com/kkkgo/PaoPaoGateWay/discussions/25#discussioncomment-7221895)。  
- 某些修改的openwrt版本会有DNS重定向的劫持选项需要手动关闭。[【参考1】](https://github.com/kkkgo/PaoPaoDNS/issues/2#issuecomment-1504708367) [【参考2】](https://github.com/kkkgo/PaoPaoDNS/discussions/111#discussioncomment-8872824)。
- 在IPv6环境下，需要关闭路由器的DNS的IPv6 DNS下发。
# 在docker上部署
尽管在这个场景下使用docker部署不太常见，但仍有很多没有开放终端的设备只能跑docker。  
以下是非常简单的docker compose的示例配置，可以根据自己的实际环境调整，或者复制给AI转换成你实际的容器环境Cli。  
把`mini-ppdns.ini`和对应你设备架构的`mini-ppdns`二进制放在`docker-compose.yml`同一目录。
```yaml
services:
  mini-ppdns:
    image: public.ecr.aws/docker/library/busybox
    container_name: mini-ppdns
    network_mode: host
    restart: unless-stopped
    volumes:
      - .:/app:ro
    working_dir: /app
    command: [ "./mini-ppdns", "-config", "mini-ppdns.ini" ]
```
此处定义网络模式是host（直接使用宿主机网络），因此不需要映射端口，可根据自己需要调整。

