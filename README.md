# mini-ppdns 二进制下载指引
本目录存放各架构编译好的 `mini-ppdns` 二进制文件。
## 文件命名规则
```
mini-ppdns_{uname -m}        # 原版
mini-ppdns_{uname -m}_upx    # UPX 压缩版（体积更小，仅建议空间有限的嵌入式设备使用）
```
在设备上运行 `uname -m` 即可得到对应的文件名后缀。
## 架构对照表
| 设备类型 | `uname -m` 输出 | 下载 | 下载（UPX 压缩版） |
|----------|----------------|------------|-----------------|
| 软路由 / 普通 x86 服务器 | `x86_64` | [mini-ppdns_x86_64](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_x86_64) | [mini-ppdns_x86_64_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_x86_64_upx) |
| ARM64 设备（树莓派3/4/5 64位、新款路由、新联发科）| `aarch64` | [mini-ppdns_aarch64](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_aarch64) | [mini-ppdns_aarch64_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_aarch64_upx) |
| ARMv7 设备（树莓派2/3 32位、部分路由）| `armv7l` | [mini-ppdns_armv7l](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_armv7l) | [mini-ppdns_armv7l_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_armv7l_upx) |
| ARMv6 设备（树莓派1/Zero、老设备）| `armv6l` | [mini-ppdns_armv6l](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_armv6l) | [mini-ppdns_armv6l_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_armv6l_upx) |
| MIPS 大端路由（部分博通/atheros）| `mips` | [mini-ppdns_mips](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_mips) | [mini-ppdns_mips_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_mips_upx) |
| MIPSEL 小端路由（MT7621、老联发科）| `mipsel` | [mini-ppdns_mipsel](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_mipsel) | [mini-ppdns_mipsel_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_mipsel_upx) |
| MIPS64 大端 | `mips64` | [mini-ppdns_mips64](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_mips64) | [mini-ppdns_mips64_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_mips64_upx) |
| MIPS64 小端 | `mips64el` | [mini-ppdns_mips64el](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_mips64el) | [mini-ppdns_mips64el_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_mips64el_upx) |
| x86 32位系统 | `i686` | [mini-ppdns_i686](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_i686) | [mini-ppdns_i686_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_i686_upx) |
| RISC-V 64位 | `riscv64` | [mini-ppdns_riscv64](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_riscv64) | [mini-ppdns_riscv64_upx](https://github.com/kkkgo/mini-ppdns/raw/refs/heads/release/mini-ppdns_riscv64_upx) |

## UPX 压缩版 vs 原版
| | 原版 | `_upx` 压缩版 |
|--|------|--------------|
| 体积 | 较大 | 约为原版 1/3 |
| 兼容性和性能 |  最佳 |  极少数内核不支持 |
| 推荐场景 | 存储充足的设备 | Flash 空间有限的路由器 |
