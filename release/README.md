# mini-ppdns 二进制下载指引

本目录存放各架构编译好的 `mini-ppdns` 二进制文件。

## 文件命名规则

```
mini-ppdns_{uname -m}        # 原版
mini-ppdns_{uname -m}_upx    # UPX 压缩版（体积更小，仅建议空间有限的嵌入式设备使用）
```

在设备上运行 `uname -m` 即可得到对应的文件名后缀。

## 架构对照表

| 设备类型 | `uname -m` 输出 | 下载文件 |
|----------|----------------|---------|
| 软路由 / 普通 x86 服务器 | `x86_64` | `mini-ppdns_x86_64` |
| ARM64 设备（树莓派3/4/5 64位、新款路由）| `aarch64` | `mini-ppdns_aarch64` |
| ARMv7 设备（树莓派2/3 32位、部分路由）| `armv7l` | `mini-ppdns_armv7l` |
| ARMv6 设备（树莓派1/Zero、老设备）| `armv6l` | `mini-ppdns_armv6l` |
| MIPS 大端路由（部分博通/atheros）| `mips` | `mini-ppdns_mips` |
| MIPSEL 小端路由（MT7621、大多数联发科）| `mipsel` | `mini-ppdns_mipsel` |
| MIPS64 大端 | `mips64` | `mini-ppdns_mips64` |
| MIPS64 小端 | `mips64el` | `mini-ppdns_mips64el` |
| x86 32位系统 | `i686` | `mini-ppdns_i686` |
| RISC-V 64位 | `riscv64` | `mini-ppdns_riscv64` |

## UPX 压缩版 vs 原版

| | 原版 | `_upx` 压缩版 |
|--|------|--------------|
| 体积 | 较大 | 约为原版 1/3 |
| 兼容性和性能 |  最佳 |  极少数内核不支持 |
| 推荐场景 | 存储充足的设备 | Flash 空间有限的路由器 |
