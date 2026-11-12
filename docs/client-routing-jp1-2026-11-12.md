# 客户端分流 v1 日常流程验收（2026-11-12）

结果：jp1 上的九组真实 CLI 验收全部通过。本轮使用 5 条规则和一个含 2 项的
本地规则集，完成普通代理模式的功能收口；没有发现需要修改 Rust 运行时的问题。
当前阶段转为 dev 变更整理与发布前审查，大列表扩容不再作为收尾前置条件。

后续提交前的 Linux release 回归另发现并修复了
[Brutal 最小窗口停滞](brutal-minimum-window.md)。本文保留下述 jp1 被测二进制的
原始结果；不将后续修复算作这轮实机测试覆盖。

## 环境和范围

- jp1：Ubuntu 24.04 x86_64，Linux `7.0.0-1012-aws`，glibc 2.39，curl 8.5.0。
- 基于 `5e1fb6a` 的未提交工作区，包含成员索引、lint 优化及此前的客户端改动。
  Rust 1.91.1 GNU Linux debug 构建，关闭 debuginfo 和 incremental；不是性能测试。
  复用现有 Docker 构建卷，本机增量目录未重建。
- 二进制 SHA-256：
  `43bdc1b9b8a465eea0cd94b60eef3d20f504703062375ca8d89b31bb9865810f`。
- 测试使用普通 `ubuntu` 账户、独立私有目录和 `HYSTERIA_PROFILE_DIR`。
  客户端、服务端与目标服务均在 jp1 回环网络；没有公网转发目标。
- 先检查端口空闲，再使用 QUIC 50000、SOCKS5 50001、HTTP 50002、TCP/UDP
  转发 50003/50004、目标 HTTP 50008、UDP echo 50009、拒绝目标 50010。
  客户端连接及 SOCKS5 UDP relay 另有内核分配的临时端口。
- 服务器通过 `direct.bindIPv4: 127.0.0.2` 发出代理请求；客户端直连来源为
  `127.0.0.1`。HTTP/UDP 目标记录实际来源，用于核对转发路径。
- 使用项目自带 `cert` 命令生成一次性服务器证书，客户端显式配置 `tls.ca` 和
  `sni: localhost`，保留证书校验。自动更新检查关闭。

## 已通过

| 流程 | 观察结果 |
| --- | --- |
| 帮助与能力发现 | 无参数、整体/角色帮助、capabilities 可用；未创建档案目录 |
| 标准链接与档案 | server share → stdin 导入 → list/show；私有权限、重复导入保护和无效覆盖保留旧文件 |
| 小规模配置与检查 | 从不同工作目录读取档案旁的规则文件；域名/后缀/IPv4/IPv6、默认代理与前置拒绝解释正确 |
| lint 与错误 | 正常配置 strict lint 通过；被遮蔽规则退出 3；空协议/端口过滤字段被拒绝；机器输出不含密码或 ANSI |
| 主动诊断 | TLS、认证、显式 TCP 与 UDP echo 检查通过 |
| TCP 实际转发 | curl 的 SOCKS5、HTTP、CONNECT 路径分别验证 direct/proxy/reject；独立 TCP 转发来源为服务端 |
| UDP 实际转发 | 同一 SOCKS5 UDP association 混用 direct/proxy/reject，拒绝后仍可直连；独立 UDP 转发通过 |
| 离线与恢复 | 停止测试服务端后直连继续成功；代理请求失败且未到达目标；恢复服务端后原客户端和原 UDP association 恢复代理 |
| 快照与退出 | 文件变更不影响活动客户端；离线 explain 读取新文件，显式重启后实际采用新规则；SIGTERM 事件顺序、退出码与档案删除通过 |

所有到达拒绝目标的请求计数均为零。生命周期事件序号严格递增；`stopping` 后只有停止事件，没有
新的连接事件。首次直连不触发代理连接。

验收夹具修正：初版误读了 explain 的字段名，现按已有 `outbound` 契约检查。
另一轮夹具使用 OpenSSL 默认生成的 `CA:TRUE` 证书，QUIC/TLS 检查失败；改用项目
自带的服务器证书生成命令后，全套通过。没有通过禁用 TLS 校验绕过问题。

## 清理与基线

测试后与清理后均复核：IPv4/IPv6 路由和策略规则、resolv.conf、resolved PID、
原有监听端点及所属 PID 保持一致。比较排除实时队列、文件描述符编号和 IPv6 RA
路由到期倒计时；原始快照仅观察到 DHCP 描述符轮换与 RA 倒计时变化。

三个远端临时目录、测试程序、配置、密钥和档案均已删除，无测试进程残留。
本地临时 SSH 私钥/证书、复用连接和上传二进制已清理。未修改 AWS 防火墙、
宿主机网络设置或现有 rc.6 服务，也未提交、推送或发布。

不含认证配置、私钥和证书的本地证据位于
`/tmp/hysteria-routing-v1-evidence.gzrmwmdf/`：最终结果、doctor JSON、explain 文本、
客户端事件、原始失败/成功记录、构建日志和前后基线。临时目录可能被系统清理。

## 复现

[独立验收脚本](../scripts/client_routing_acceptance.py)仅依赖 Linux、Python 3、curl
和待测 Hysteria 二进制。无需 root，不自动安装依赖；不随 cargo test 执行。
请在授权测试机上选择全新的私有目录：

```shell
work=$(mktemp -d /tmp/hysteria-routing-v1.XXXXXXXX)
python3 scripts/client_routing_acceptance.py \
  --binary /path/to/linux/hysteria --work "$work"
```

运行器自动选择 50000–50199 中的空闲端口组，有单项超时与 180 秒运行阶段超时，成功或
异常均回收自己启动的子进程。目录保留结果及生成的秘密材料；完成检查后仅删除
这次创建的目录。宿主机前后基线是本次额外审计，不由该运行器自动完成。

这次验收不涵盖公网性能、真实网络切换、休眠、小时/日级运行或桌面网络管理器。
没有运行 TUN 或改变系统 DNS；此前 Linux TUN 隔离验收与尚待验证的整机边界
继续见 [Linux 清单](linux-validation-2026-11-11.md)。macOS/Windows 平台验收仍需
按其支持范围独立安排。
