# mini-ppdns 二进制下载指引

本目录存放各架构编译好的 `mini-ppdns` 二进制文件。

## 下载

先用 `uname -m` 确认你的设备架构，然后下载对应文件：

| 架构 (`uname -m`) | 适用设备 | 下载 |
| --- | --- | --- |
| `x86_64` | 64 位 PC / 服务器 / 大多数虚拟机、软路由 | [mini-ppdns_x86_64](https://github.com/__REPO__/raw/release/mini-ppdns_x86_64) |
| `aarch64` | 64 位 ARM（多数现代路由器、树莓派 3/4/5 64 位） | [mini-ppdns_aarch64](https://github.com/__REPO__/raw/release/mini-ppdns_aarch64) |
| `armv7l` | 32 位 ARMv7（老旧路由器、树莓派 2） | [mini-ppdns_armv7l](https://github.com/__REPO__/raw/release/mini-ppdns_armv7l) |
| `armv6l` | 32 位 ARMv6（树莓派 1 / Zero） | [mini-ppdns_armv6l](https://github.com/__REPO__/raw/release/mini-ppdns_armv6l) |
| `i686` | 32 位 x86 | [mini-ppdns_i686](https://github.com/__REPO__/raw/release/mini-ppdns_i686) |
| `riscv64` | RISC-V 64 位（glibc 动态） | [mini-ppdns_riscv64](https://github.com/__REPO__/raw/release/mini-ppdns_riscv64) |
| `mips` | MIPS 大端（部分老路由器） | [mini-ppdns_mips](https://github.com/__REPO__/raw/release/mini-ppdns_mips) |
| `mipsel` | MIPS 小端（如 MT7621 等常见路由器） | [mini-ppdns_mipsel](https://github.com/__REPO__/raw/release/mini-ppdns_mipsel) |
| `mips64` | MIPS64 大端 | [mini-ppdns_mips64](https://github.com/__REPO__/raw/release/mini-ppdns_mips64) |
| `mips64el` | MIPS64 小端 | [mini-ppdns_mips64el](https://github.com/__REPO__/raw/release/mini-ppdns_mips64el) |
