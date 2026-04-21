# https://blog.03k.org/post/mini-ppdns.html
###  [release下载](https://github.com/kkkgo/mini-ppdns/tree/release)
# mini-ppdns 
专注于 DNS 故障转移的迷你DNS转发器。   
`mini-ppdns` 是从`PaoPaoDNS`项目精简修改而来的纯粹转发器，致力于提供极致轻量化且高效的平滑 DNS 故障转移体验。    
Hook功能通过定时执行外部命令来主动检测主DNS的可用性，可以用脚本扩展覆盖更多主备切换场景。    
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

- `-dns`：本地自建主 DNS 上游（必填），支持多个地址以逗号分隔，如 `10.10.10.8,10.10.10.9`。  
- `-fall`：备用/运营商 DNS 上游（必填），支持多个地址以逗号分隔。  
- `-listen`：可以指定监听地址和端口，默认是监听所有可监听的私有地址（跳过公网地址）。  
  - `mini-ppdns -dns 10.10.10.8 -fall 223.5.5.5 -listen 127.0.0.1:53`  
- `-aaaa`：可以指定 AAAA 记录的处理模式（默认为 no，屏蔽 AAAA 查询）：  
  - `no`（默认）：屏蔽所有 AAAA 查询，直接返回空结果。  
  - `yes`：允许 AAAA 查询，走正常的主 DNS→备用 DNS 故障转移逻辑。  
  - `noerror`：允许 AAAA 查询，若主 DNS 返回 NOERROR（即使 Answer 为空），直接采信该结果，不再尝试备用 DNS。
- `-force_fall`：可以指定某些客户端 IP 段总是走备用 DNS。  
  - `mini-ppdns -dns 10.10.10.8 -fall 223.5.5.5 -force_fall=192.168.1.10,192.168.2.0/24`  
- `-qtime`：指定故障转移的延迟阈值（单位 ms，默认 250）。  
- `-lite`：是否开启精简响应模式（默认为 yes，仅保留请求的主记录，去掉无关记录）。   
- `-debug`：输出详细的调试日志。
- `-d`：在后台运行。
- `-version`：打印版本信息并退出。
- `-config`：可以指定加载配置文件，可以配置 `mini-ppdns.ini` 如下：
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
# 若未指定listen，或者指定为通配地址 `0.0.0.0:<port>` 或 `[::]:<port>`，
# 会自动展开为本机所有私有/环回地址（跳过公网），避免将 DNS 暴露到公网接口
[listen]
127.0.0.1:53
192.168.1.1:53

# 可以指定某些IP段总是走运营商/故障转移的DNS
[force_fall]
# 支持以下三种写法：单个 IP、CIDR 端、以及特定的 IP Range
# FakeIP场景可以利用这个功能，间接实现某些设备不走代理
192.168.1.10
192.168.2.0/24
192.168.3.2-192.168.3.100
# 在IP前面加^号可以取反，比如^192.168.1.10表示除了192.168.1.10以外的IP段都走运营商/故障转移的DNS
# 所有取反的规则是AND的逻辑，也就是说，只有所有取反的规则都满足，才走运营商/故障转移的DNS
# 非取反的规则是OR的逻辑，也就是说，只要有一个非取反的规则满足，就走运营商/故障转移的DNS
# 当同时存在非取反与取反规则时，非取反规则优先判定；取反规则仅在不匹配任何非取反规则时生效。
^192.168.1.123-192.168.1.125
^192.168.1.126
^192.168.10.0/24
# FakeIP场景可以利用取反功能，间接实现只有某些设备走代理
[adv]
# 转移延迟阈值（毫秒）
qtime=250
# 是否开启 IPv6 aaaa记录查询解析（no/yes/noerror）
# no：屏蔽aaaa查询直接返回空（默认）
# yes：允许aaaa查询，走正常故障转移逻辑
# noerror：当主DNS返回NOERROR时直接采信（即使answer为空），仅主DNS出错才走备用DNS
aaaa=no
# 是否开启精简响应模式，去掉无关记录（yes/no）
lite=yes
# 信任主DNS返回的指定rcode，直接采信不再请求备用DNS（默认为空，不信任）
# 例如：trust_rcode=0,3 表示信任NOERROR(0)和NXDOMAIN(3)
# 适用于某些信任"屏蔽记录"的场景，比如主DNS返回了空记录的noerror，但实际上备用DNS可以正常解析出记录。
# trust_rcode=0,3
# bogus-priv功能（默认启用，等效于OpenWRT的 option boguspriv '1'） 设置为0可以关闭此功能
# boguspriv=1
# 手动指定DHCP lease文件路径，用于本地PTR记录解析（支持逗号分隔多个文件）
# 初始化时所有文件都不存在则不启用PTR解析，该功能在openwrt等路由器系统上会自动查找可用配置，无需指定
# lease_file=
# 手动指定hosts文件路径，用于本地记录解析（支持逗号分隔多个文件）
# 支持正向（A/AAAA）和反向（PTR）查询，格式同 /etc/hosts
# 不配置时自动尝试 /etc/hosts，支持热重载（每5秒检测文件变化）
# hosts_file=
[hosts]
# 在配置文件中直接写入hosts记录，格式同 /etc/hosts
# 同时支持正向（A/AAAA）和反向（PTR）查询
# [hosts]条目优先级高于hosts_file文件中的同名条目
# paopao.dns 总是用主DNS解析，除非hosts已经有定义
#10.10.10.53 paopao.dns
#1.2.3.4 example.com

# Hook功能通过定时执行外部命令检测主DNS状态,故障时自动切换至备用DNS，恢复后自动切回主DNS
[hook]
# 执行的命令,比如检测socks5代理是否可以访问网络
exec="curl -o /dev/null -s -w %{http_code} --proxy socks5h://10.10.10.3:1080 http://www.google.com/generate_204"
# 执行命令的退出状态码（exit status），比如0表示成功，不指定的时候则不检查状态码
exit_code=0
# 执行命令的输出中是否包含某个关键字，不指定的时候则不检查输出
keyword="204"
# 检测间隔，每sleep_time秒检测一次，默认值为60
sleep_time=60
# 重试间隔，检测失败后等待retry_time秒后重试，默认值为5
retry_time=5
# 当连续count次检测失败后，定义主DNS为故障，默认值为10
count=10
# 当因为hook功能切换到备用DNS后，执行的命令（如发送通知）
# 注意:触发时会自动清空所有现存的系统DNS缓存，避免受主DNS的过时记录影响。
# switch_fall_exec命令会自动延迟 retry_time / 2 配置的时间后才执行，以等待备用DNS切换生效
# 从而确保执行switch_fall_exec脚本时系统已可以使用备用DNS正常解析（如上报时所用的通知域名）
switch_fall_exec="curl -sk -o /dev/null --data 'Main DNS is DOWN!' --retry 3 https://ntfy.sh/mydns_status"
# 当因为hook功能切换回主DNS后，执行的命令（如发送通知）
switch_main_exec="curl -sk -o /dev/null --data 'Main DNS is UP!' --retry 3 https://ntfy.sh/mydns_status"
```

---
# 在openwrt路由器上部署
在openwrt上部署说起来简单也复杂，因为很多openwrt里面有各种神神秘秘的插件互相干扰。其中不少会劫持DNS，此处部署过程仅包含一些常见的坑和注意事项。当然部分过程也适用于其他linux系统。  
- 去[release](https://github.com/kkkgo/mini-ppdns/tree/release)下载适合你的硬件架构的二进制文件。如果不清楚自己的硬件是什么架构，可以在终端输入`uname -m`。其中release名字带UPX的是为了给一些储存空间紧张的设备用的，如果你的设备空间充足下正常版本即可。
- 把`mini-ppdns`上传到你的设备，为了方便你可以上传到`/usr/sbin/mini-ppdns`,加执行权限`chmod +x /usr/sbin/mini-ppdns`。将你的配置文件储存在`/etc/mini-ppdns.ini`，然后执行`mini-ppdns -config /etc/mini-ppdns.ini`看看是否输出正常（比如提示某个端口已经被监听）。
- 添加自启动脚本。在openwrt上最简单的是编辑 `/etc/rc.local`，在 `exit 0` 之前添加你的启动命令，带上 `-d` 参数，程序会自动到后台，不会阻塞启动。当你修改了局域网的IP段或者配置，你需要重新启动`mini-ppdns`。

```bash
/usr/sbin/mini-ppdns -config /etc/mini-ppdns.ini -d
exit 0
```
或者写一个守护脚本加计划任务或者修改服务，此处提供了一个参考脚本：
https://github.com/kkkgo/mini-ppdns/blob/main/mini-ppdns.sh  
使用方法，把脚本上传到`/usr/sbin`重命名为`/usr/sbin/mini-ppdns`加执行权限，`crontab -e`编辑计划任务：`* * * * * /usr/sbin/mini-ppdns.sh`即可。脚本启动之前检测是否已经存在mini-ppdns进程，如果存在就直接退出，因此可以直接让计划任务每分钟执行来作为守护。执行`mini-ppdns.sh restart`可以重载配置。
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
    image: public.ecr.aws/sliamb/tool
    container_name: mini-ppdns
    network_mode: host
    working_dir: /app
    entrypoint: ["/app/mini-ppdns"]
    command: ["-config", "mini-ppdns.ini"]
    volumes:
      - ./:/app:ro
    restart: unless-stopped
```
此处定义网络模式是 host（直接使用宿主机网络），因此不需要映射端口，可根据自己需要调整。