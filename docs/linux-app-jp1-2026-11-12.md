# jp1 真实 CLI 应用与 Fake-IP 验收（2026-11-12）

结果：当前工作区在隔离的 Linux TUN / systemd-resolved 环境中，通过真实 curl
请求、域名分流、容量扩展、服务端离线/恢复和重启后保留地址的验收。没有发现需要
修改 Rust 数据路径的问题。本轮新增持久化的验收脚本和记录，没有提交或发布。

## 环境与边界

- 复用 jp1（Ubuntu 24.04 x86_64）的实际 Linux 内核、systemd-resolved、glibc、
  D-Bus 和 curl 8.5.0；HTTP/DNS/echo 目标均为隔离环境内的测试服务。
- 基于 `5e1fb6a` 的未提交工作区，包含本轮 Fake-IP 容量与批量持久化实现。
  Rust 1.91.1 GNU Linux debug 构建，不是 release 性能测试或发布包。
- 二进制 SHA-256：
  `18c16208fdab71cef4a4462a4186dd45a5aca4a5cbab780f28418271020ae72d`。
- 外层只读记录宿主机基线；测试进程进入私有 mount、PID、network namespace，
  使用私有 `/run`、`/etc/systemd`、D-Bus 和 resolved。无宿主机出口或 NAT。
- QUIC 50000、DNS fixture 50053、echo 50080/50081、HTTP 50082 均只在隔离网络。
  标准 53 仅用于其中的 DNS fixture / resolved stub，不占用宿主机端口。
- 使用一次性叶证书和显式客户端 CA 校验；测试 resolver 关闭 DNSSEC/DoT，
  仅用于测试配置，没有改动宿主机的 DNS 安全策略。

## 已通过

| 场景 | 观察结果 |
| --- | --- |
| 只读 doctor | 缓存未创建，接口与规则未改变 |
| 初始容量 | doctor 后预置 4090 条；显式 maxEntries=8192，默认值不变 |
| 仅启动 TUN | resolved 仍返回真实 IP；启动成功不能证明 DNS 已接管 |
| 显式 per-link DNS | stub UDP/TCP、glibc、resolvectl 均获得 Fake-IP |
| 实际 HTTP 请求 | curl -4 / -6 均连接对应地址族的 Fake-IP；direct / proxy 成功 |
| 路径归属 | HTTP 目标核对连接来源，区分客户端直连与服务端代理出口 |
| reject 规则 | 两种应用地址族均请求失败，没有成功的 HTTP 响应 |
| 并发新域名 | 8 个 curl 工作线程访问 128 个新域名，全部成功，缓存恰好增加 128 条 |
| 跨越旧容量 | 最终 4221 条，超过旧默认 4096；原映射与新映射均可用 |
| 服务端离线 | direct 请求继续成功；proxy 请求失败，不回退直连 |
| 服务端恢复 | 同一运行客户端重新完成代理请求，无需客户端重启 |
| SIGTERM | TUN 与自有规则清理；无需手动 flush 即恢复真实 DNS 结果 |
| 客户端重启 | 使用同一缓存，DNS 与转发再次成功，缓存文件完整一致 |
| 应用保留地址 | curl --resolve 显式使用重启前 Fake-IP，direct/proxy 的 IPv4/IPv6 请求均成功 |
| 显式 revert | revert TUN DNS 后停止客户端，普通解析与网络基线恢复 |

应用保留地址测试使用 curl `--resolve`，是可控模拟，不代表测试了浏览器自身缓存。
`curl -6` 限定的是应用到虚拟地址这一段；客户端或服务端找回域名后可以解析并连接
IPv4 后端。首轮夹具错误地要求后端也必须 IPv6，导致断言失败；修正为分别检查
应用连接地址族和目标所见来源后全套通过。没有据此修改实际代理行为。

## 清理与证据

两轮结束均比较宿主机基线；归档与清理后再次核对：IPv4/IPv6 路由和策略规则、
resolv.conf、原 resolved PID、七个现有 Hysteria/Snell 监听端点及 PID、命名网络
空间列表一致。原 resolved 保持 active。未修改 AWS 防火墙或现有 rc.6 服务。

远端两处临时目录、测试二进制、配置、密钥、证书和缓存已删除；没有测试二进制
进程残留。本地临时 SSH 私钥/证书和上传用二进制副本已删除。

本地证据：`/tmp/hysteria-app-qa-results.log`、`/tmp/hysteria-app-qa-audit.log`，
以及 `/tmp/hysteria-app-qa-evidence/` 中的不含认证凭据的归档。归档只包含测试日志、只读诊断和
网络基线，不包含认证配置、私钥、证书或缓存内容；临时文件可能被系统清理。

可重复脚本及前置条件已保存到
[Linux 验收脚本](../scripts/linux_tun_acceptance/README.md)。Python 语法检查和
仓库 diff 空白检查通过。运行脚本需要明确选择临时目录和待测 Linux 二进制，
不会随普通 cargo test 自动执行。

## 后续方向

此轮完成真实 CLI 应用的隔离验收，仍不涵盖浏览器 DoH、系统 DoT/严格 DNSSEC、
真实桌面网络管理器、休眠/漫游、整机断电、生产公网吞吐或小时/日级稳定性。

后续已完成可选的 `doctor client --dns DOMAIN` 实测诊断，并在 jp1 验证
“已启动但 DNS 绕过”与“新查询进入 Fake-IP”两种情况，见
[DNS 接管验收](linux-dns-probe-jp1-2026-11-12.md)。追加日志仍是独立存储优化；
当前待测范围为上面的整机、外部网络与长期运行场景。
