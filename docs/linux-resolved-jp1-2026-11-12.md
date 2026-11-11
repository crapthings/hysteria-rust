# jp1 TUN 与 systemd-resolved 验收（2026-11-12）

结果：在 jp1 的隔离环境中，显式 per-link DNS 配置后的 Fake-IP 解析、双栈转发、
正常停止恢复和重启持久化通过。本轮没有发现需要修改 Rust 数据路径的问题。

重要观察：**仅启动 TUN 时，resolved 仍可通过已有物理接口 DNS 返回真实 IP。**
DNS 查询成功不代表进入了 Fake-IP，也不证明域名分流正在生效。

## 环境与隔离

- AWS Lightsail 东京 `speedtest-jp1`，Ubuntu 24.04 x86_64，内核 `7.0.0-1012-aws`。
- systemd-resolved `255.4-1ubuntu8.18`；使用系统实际提供的 daemon、D-Bus、
  resolvectl 和 glibc `getaddrinfo`。
- 当前 dev 工作区 GNU Linux debug 构建，非发布包；SHA-256：
  `ff1221edf1071f333fc082f0ebd049d852bd47eed822a7b3951d3fddd312ea05`。
- 整个测试在私有 mount、PID、network namespace 内执行；`/run` 和
  `/etc/systemd` 使用私有 tmpfs。独立 D-Bus 与 resolved 不连接宿主机总线。
- 客户端与服务端用 veth 相连。QUIC 50000、受保护的上游 DNS TCP 50053、
  TCP/UDP echo 50080/50081 均在隔离网络中。
- 标准 DNS 53 端口仅用于隔离环境内的 resolved stub 和 DNS fixture，
  没有占用宿主机 53 或其他现有端口，也没有开放公网测试端口。
- resolved 测试配置明确关闭 DNSSEC、DNS-over-TLS、LLMNR 和 mDNS；使用缓存。
  Hysteria 连接使用生成的叶证书和显式 CA 校验，没有关闭代理 TLS 验证。

本轮检验的是实际 Linux 内核、实际 resolved 与本地测试 DNS/echo 的组合，
不是公网 DNS、浏览器或生产桌面整机的全面验收。

## 验证过程与结果

| 场景 | 结果 |
| --- | --- |
| TUN 启动前 | resolved 经物理测试接口解析得到真实 A/AAAA 地址 |
| 只读 doctor | 配置通过；没有创建 Fake-IP 缓存或锁，没有改变接口/策略规则 |
| 仅启动 TUN | 标准 53 上游对照仍返回真实 IP，不能假定 DNS 自动接管 |
| 显式配置 TUN DNS | resolved stub 的 UDP/TCP 查询均返回 Fake-IP |
| glibc 解析 | `getaddrinfo` 获得与 stub 查询一致的 A/AAAA Fake-IP |
| D-Bus 查询 | `resolvectl query --cache=no` 从 TUN DNS 获得 Fake-IP |
| 域名 direct | IPv4/IPv6 TCP 和 UDP echo 均通过 |
| 域名 proxy | IPv4/IPv6 TCP 和 UDP 经 Hysteria 转发均通过 |
| SIGTERM | TUN 设备与自有策略/路由清理，命名空间主表和规则恢复基线 |
| 停止后的 DNS | 未手动 flush 即恢复真实 A/AAAA；物理接口原 DNS 配置保留 |
| 重启 | 重新设置 per-link DNS 后，映射文件保持一致，双栈转发再次通过 |
| 显式 revert | 接口存在时 `resolvectl revert`，再停止客户端并 flush，普通 DNS 恢复 |

显式接入时使用下列设置（只在隔离环境执行）：

```shell
resolvectl dns hytunqa 198.18.0.1
resolvectl domain hytunqa '~.'
resolvectl dnssec hytunqa no
resolvectl dnsovertls hytunqa no
resolvectl flush-caches
```

DNSSEC/DoT 两项与测试基线一致；这不是对用户现有安全策略的自动降级建议。
实际机器应先评估其 resolver 策略。本轮没有测试 DNSSEC 严格验证或 DoT 模式。

停止恢复测试使用相同的测试域名，检查 resolved 在 TUN link 消失后回到原物理
DNS 路径。该结果**不保证浏览器或其他应用同步丢弃自己缓存的 Fake-IP**，也不
覆盖 SIGKILL、残留策略和任意第三方网络管理器。

初始夹具曾使用 50053 上游并观察到真实 IP；随后增加标准 53 上游对照，得到
相同的“不能假定自动接管”结果。未对具体 socket 缓存/绑定机制做内核跟踪，
因此不将这一观察归因于某个未证实的实现原因。

## 清理与宿主机核对

测试退出时关闭所有隔离进程，销毁网络命名空间和私有挂载。随后删除远端测试
二进制、脚本、配置、证书、Fake-IP 缓存与锁文件；本地临时 SSH 密钥/证书也已删除。

前后基线一致：

- 宿主机 IPv4/IPv6 路由和策略规则（比较时排除自然递减的 `expires`）；
- `/etc/resolv.conf` 内容及原 systemd-resolved 主进程 PID；
- 现有 Hysteria/Snell 的七个监听端点及进程 PID；
- 宿主机命名网络空间列表。

原 resolved 保持 active。未替换现有服务二进制，未修改 AWS 防火墙、宿主机
DNS、路由或业务端口，未提交/推送/发布代码。

## 仍需验证

- 真实桌面/整机网络管理器组合，以及 Wi-Fi/有线切换和休眠唤醒。
- 浏览器 DoH、系统 DoT、严格 DNSSEC、应用自身缓存和 `libnss_resolve` 的独立路径。
- SIGKILL 后的 DNS/策略恢复、生产机已有规则共存及权限受限服务账户。
- 公网性能、长时间运行和不同 systemd-resolved 版本。

本地原始结果：`/tmp/hysteria-jp1-resolved-results.log`；最终审计：
`/tmp/hysteria-jp1-resolved-audit.log`。不含测试私钥/认证配置的证据归档位于
`/tmp/hysteria-resolved-evidence/evidence.tar`；夹具为 `/tmp/hysteria-resolved-qa.py`
和 `/tmp/hysteria-jp1-tun-test.py`。这些临时文件可能被系统清理，仓库仅保留本报告。
