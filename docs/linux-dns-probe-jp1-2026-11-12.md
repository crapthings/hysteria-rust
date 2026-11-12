# jp1 DNS 接管实测诊断验收（2026-11-12）

`doctor client --dns DOMAIN` 在真实 Linux 内核、glibc、systemd-resolved 与 TUN 的
隔离组合中通过验收：能够区分“已启动 TUN，但系统 DNS 仍绕过”和“新查询进入
Fake-IP，且地址与所选缓存匹配”。本轮同时通过了本地规则集的 TUN 转发验收。

## 环境

- jp1，Ubuntu 24.04 x86_64，Linux `7.0.0-1012-aws`，systemd-resolved
  `255.4-1ubuntu8.18`。
- 当前未提交工作区，Rust 1.91.1 GNU Linux debug 二进制；不作为性能测量。
- 被测 SHA-256：`d7440328f802746e47910c976b65bfc7b086e2122afb23cf9cbcf341816e8853`。
  验收后仅补充帮助文本与文档。
- 使用[可重复脚本](../scripts/linux_tun_acceptance/README.md)的私有 mount/PID/network
  namespace、独立 D-Bus/resolved 和 veth 网络；无宿主机出口或 NAT。
- QUIC 50000、DNS 50053、echo 50080/50081、HTTP 50082；53 仅供隔离环境的
  DNS fixture / resolved stub 使用。没有占用宿主机现有业务端口。
- 配置显式设为 8192 容量，预置 4090 条；`direct(set:direct_domains)` 使用配置目录
  中的 `direct-domains.txt`，不改变默认容量或原有服务配置。

## 观测

| 阶段 | `dns_capture` 结果 | IPv4 / IPv6 | 缓存变化 |
| --- | --- | --- | --- |
| TUN 已启动，尚未设置 per-link DNS | `non_fake_answers`，退出 3 | `192.0.2.2` / `fd42:5000::2`，均 fail | 文件字节不变 |
| 显式设置 TUN per-link DNS 后 | `matched_cache`，退出 0 | `198.18.15.253` / `fd00:198:18::ffd`，均 pass | 恰好新增一个生成的探测名字，旧编号不变 |

两次调用都使用 `--dns direct.test --timeout 5s --output json`；每次生成不同的
`hy2-probe-<128-bit nonce>.direct.test`，经实际系统 resolver 查询。
没有套用活动 TUN 会触发的启动前策略/CAP_NET_ADMIN 检查，也没有执行 `--connect`
服务端探测。配置本地规则集加载成功。

随后完整重跑并通过：curl 双栈 Fake-IP 输入、目标侧核对直连/代理来源、拒绝规则、
128 个新域名并发请求、服务端离线直连继续可用/代理失败及恢复、SIGTERM 后普通
DNS 恢复、重启后保留旧 Fake-IP 请求和完整缓存一致性。最终缓存 4222 条。
应用输入地址族与后端实际出站地址族分别检查，不混为一谈。

## 自动回归

- macOS workspace 测试和严格 Clippy 通过。
- Linux DNS 探测单元测试 5 项、CLI 契约 37 项、客户端体验 4 项、DNS CLI 2 项、
  TUN 只读预检 1 项，以及严格 Clippy 通过。
- 单元测试覆盖真实/混合/错误合成地址、错误缓存对应关系、缺失/满缓存、IPv6 未
  返回时的 skip、输出大小限制，以及超时/取消后的子进程终止与回收。
- 这些测试不修改宿主机 DNS，不启动生产服务；现有 vendored h3 生命周期警告保留。

## 清理与限制

前后及清理后的宿主机 IPv4/IPv6 路由和策略规则、resolv.conf、原 resolved PID、
七个 Hysteria/Snell 监听端点及 PID、命名网络空间列表一致；原 resolved 保持 active。
远端测试二进制、脚本、配置、证书、缓存及目录已清理，无测试解析子进程残留。
本地临时 SSH 私钥/证书及上传副本已删除。没有修改 AWS 防火墙、现有 rc.6 服务，
也没有提交、推送或发布。

原始结果：`/tmp/hysteria-dns-live-results.log`；最终审计：
`/tmp/hysteria-dns-live-audit.log`；不含认证配置、密钥、证书和缓存内容的归档位于
`/tmp/hysteria-dns-live-evidence/evidence.tar.gz`。临时文件可能被系统清理。

诊断只证明本次系统解析与指定磁盘缓存的对应关系；不证明 TUN 进程所有权、浏览器
DoH 或所有应用都被接管。真实桌面、其他 NSS/DoT/DNSSEC 策略、网络切换和长期运行
仍待验收。超时/取消的回收由自动测试覆盖，此次 jp1 验收验证了正常的失败/成功路径。
