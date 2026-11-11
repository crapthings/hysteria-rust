# 2026-11-11 开发版 Linux 验收清单

这份清单用于在 Linux 上验收本轮开发改动，并与正在使用的 rc.6 对照。
复选框表示**尚待人工确认**，不表示实现缺失。

## 1. 版本和范围

记录本清单时：

- `dev` 已推送至 `111ddac`：包含此前依赖升级、状态统计、masquerade、ECH、Cloudflare ACME 修正及 systemd 管理。
- 客户端初始化/引导/诊断、`server share`、help 排序、Realm 分享/引导/诊断与新增互通测试，**仍在本地工作区，尚未提交或推送**。
- 因而只拉取此时的远端 `dev`，拿不到全部待测功能。测试前应先确认这些工作区改动已包含在构建源中。
- 当前包版本仍可能显示 `0.1.0-rc.6`。不能只凭 `hysteria version` 判断是不是本轮开发版；同时记录 Git 提交、工作区状态和二进制 SHA-256。

优先级：

| 优先级 | 含义 |
| --- | --- |
| P0 | 日常使用前优先完成，失败需阻止替换现有部署 |
| P1 | 使用对应功能前完成 |
| P2 | 压力、兼容性扩展和长期运行观察 |

环境标签：**Linux 专项**、**真实外部服务**、**真实 NAT**、**跨平台回归**。

### 已完成的验证，不等于 Linux 实机验收

- macOS 开发环境的工作区测试、Clippy、格式检查。
- Linux 容器中的 systemd unit 语法检查；**没有真实启动服务或重启 Linux 系统**。
- 临时文件/模拟 systemctl 测试：安装顺序、配置校验、实例选择、冲突保护及卸载保留配置。
- 本机客户端诊断：正常/错误认证、超时、离线不发包、不占用代理监听端口。
- ECH 生成/轮换/退役及拒绝策略测试；此前已跑 Go v2.13.0 双向互通和 Chrome 模式测试。
- Cloudflare API 响应处理的本地模拟测试；**没有使用真实 Token 签发证书**。
- Realm 本地模拟 STUN/协调服务测试：Rust ↔ Rust、Go v2.13.0 ↔ Rust TCP/UDP、错误凭据、过期会话重新注册并恢复连接。
- Realm 分享链接按当前官方规范做了 Rust 往返测试；**没有证明 Go v2.13.0 的 CLI 能解析较新的组合分享 scheme**。

## 2. 测试准备与记录

建议保留 rc.6 的二进制、配置和服务，开发版使用独立目录、实例名、端口和 ACME 缓存。
下列命令是供测试人员执行的步骤，本次整理文档不会执行它们。

```bash
# 在测试源代码目录记录
uname -a
cat /etc/os-release
rustc --version
cargo --version
git rev-parse HEAD
git status --short
systemctl --version

# 如在 Linux 本机编译；项目要求 Rust 1.91 系列或兼容版本
cargo build --locked --release -p hysteria-cli --bin hysteria
sha256sum target/release/hysteria
```

后文约定测试二进制已放到一个持久位置：

```bash
HY_TEST_BIN=/opt/hysteria-dev/hysteria
"$HY_TEST_BIN" version
"$HY_TEST_BIN" help
"$HY_TEST_BIN" help server
"$HY_TEST_BIN" help client
"$HY_TEST_BIN" help service
```

- [ ] **P0 / Linux 专项**：在实际部署架构上成功构建或运行（至少你的目标 x86_64/ARM64）；没有动态库缺失或 CPU 指令不兼容。
- [ ] 记录内核、systemd 版本、架构、网络拓扑、Go 对照版本、开发版 SHA-256。
- [ ] 测试配置中的监听端口不与 rc.6 冲突；统计、ACME HTTP/TLS 验证和本地代理端口也单独规划。
- [ ] 二进制、配置及工作目录在开机后仍存在；不要从临时构建目录安装长期服务。

## 3. P0：Linux systemd 服务管理【Linux 专项，重点】

实现入口：`hysteria service`。当前仅支持 **Linux systemd 系统服务，运行身份为 root**。
`install` 默认立即启动并启用开机自启；本节会实际创建服务，应使用专用测试实例。

### 3.1 单实例安装与路径

在放置测试配置及相对路径证书的工作目录执行：

```bash
"$HY_TEST_BIN" check server -c server-a.yaml
sudo "$HY_TEST_BIN" service install server --name qa-server-a -c server-a.yaml
"$HY_TEST_BIN" service status qa-server-a
"$HY_TEST_BIN" service logs qa-server-a
systemctl cat hysteria-qa-server-a.service
```

- [ ] unit 的二进制、配置和 `WorkingDirectory` 都是预期绝对路径；相对证书、ACL、ECH、ACME 路径仍然可用。
- [ ] 服务进入运行状态；另用真实客户端完成代理访问。`active` 本身不能证明代理就绪或 ACME 已完成。
- [ ] `systemctl is-enabled hysteria-qa-server-a.service` 显示启用。
- [ ] SSH 断开/重新登录后服务继续运行，日志仍可查询。
- [ ] **人工重启测试 Linux 后**，服务自动恢复，配置/证书/ACME 缓存可读取。
- [ ] 测试含空格、`%`、`$` 的路径，确认执行参数没有被 systemd 错误展开。
- [ ] 符号链接路径的行为符合预期：安装记录的是规范化目标，之后改变链接目标不会自动更新服务。

### 3.2 安装开关、多实例及不覆盖

```bash
sudo "$HY_TEST_BIN" service install server --name qa-server-b -c server-b.yaml --no-start --no-enable
"$HY_TEST_BIN" service list
sudo "$HY_TEST_BIN" service start qa-server-b
"$HY_TEST_BIN" service status qa-server-b
```

- [ ] `--no-start --no-enable` 安装后既未运行，也未启用开机自启。
- [ ] 两个实例用不同监听和状态端口，可以同时代理；停止一个不影响另一个。
- [ ] 多实例时 `service status` 列出全部；省略名称的 start/stop/restart/logs/uninstall 报告歧义，不猜测目标。
- [ ] 在只有一个受管实例的隔离环境里，不带名称的操作能选择该实例。
- [ ] 重复安装同名实例失败，原 unit、配置和运行进程不被覆盖。
- [ ] 与已有非本工具创建的 unit、alias、软链接发生名称冲突时，不覆盖。
- [ ] 客户端实例也可用 `service install client --name qa-client -c client.yaml` 安装；先用普通 SOCKS5 配置测试，TUN 单列后测。

### 3.3 失败、重启、日志和卸载

```bash
sudo "$HY_TEST_BIN" service restart qa-server-a
"$HY_TEST_BIN" service logs qa-server-a --follow
# 手动 Ctrl+C 退出日志跟随；不应停止被观察的服务。
```

- [ ] 非 root 执行修改操作时，给出可复制的提权命令；不会自行弹出提权或执行 sudo。
- [ ] 故意写错配置后执行 `restart`：离线校验失败，原运行进程仍在，连接不因该命令被主动停止。
- [ ] 恢复配置后能正常重启。注意：运行期失败不保证回滚到旧进程，不能把它视为热更新。
- [ ] 用测试端口冲突、缺失证书制造启动失败：命令返回失败，提供日志/恢复指引，保留可管理的注册项。
- [ ] 进程异常退出后的自动重启与频率限制符合 unit 设置；没有无限高速重启。
- [ ] `stop` 能经 SIGTERM 退出并释放监听端口，不自动取消开机自启。
- [ ] 普通用户无 journal 权限时错误明确；提权后能读取日志。

完成后只清理已创建的测试实例：

```bash
sudo "$HY_TEST_BIN" service uninstall qa-server-a
sudo "$HY_TEST_BIN" service uninstall qa-server-b
# 若本次创建过客户端实例，再执行：
# sudo "$HY_TEST_BIN" service uninstall qa-client
```

- [ ] unit 和自启注册被移除，配置、证书、密钥、ACME 缓存及二进制保留。
- [ ] rc.6 原有服务和其他实例不受影响。

## 4. P0：普通客户端/服务器回归【跨平台回归，Linux 实机】

- [ ] Rust server + 现有 Go/Surge 客户端能正常连接。
- [ ] Rust client + Go server 能正常连接；需要时再测 Rust ↔ Rust。
- [ ] 实际 TCP 下载/上传、UDP 转发、并发连接和重新连接正常。
- [ ] 正确密码可用，错误密码拒绝；错误证书名/指纹不得连接成功。
- [ ] 普通 TLS、实际使用的 Salamander/Gecko、端口跳跃分别复测。
- [ ] SIGTERM/Ctrl+C 退出后没有残留代理监听；UDP 会话及后台任务合理回收。
- [ ] 与 rc.6 用相同服务端/线路/配置测吞吐、延迟、CPU、RSS，记录样本和时长，不把线路波动当成代码性能变化。

可重复的本地测试（不会替代真实线路测试）：

```bash
cargo test --locked --workspace
# 设置为你准备好的 Go v2.13.0 对照二进制绝对路径：
HYSTERIA_GO_BIN=/path/to/hysteria-go cargo test --locked -p hysteria-cli --test go_interop -- --nocapture
HYSTERIA_GO_BIN=/path/to/hysteria-go cargo test --locked -p hysteria-cli --test realm_smoke -- --nocapture
```

未设置 `HYSTERIA_GO_BIN` 时，对应互通用例可能跳过；不能仅凭测试总体通过认定已测过 Go。

## 5. P1：客户端引导、诊断、help 与分享【跨平台回归】

```bash
"$HY_TEST_BIN" guide client -c client.yaml
"$HY_TEST_BIN" check client -c client.yaml
"$HY_TEST_BIN" doctor client -c client.yaml
"$HY_TEST_BIN" doctor client --connect --timeout 10s -c client.yaml
"$HY_TEST_BIN" doctor client --connect -c client.yaml --output json
```

- [ ] 导入真实可用链接后默认只监听 `127.0.0.1:1080`，没有开启系统代理/TUN。
- [ ] 模板中的占位服务器/密码有明确编辑提示；已存在文件不覆盖，新文件 Unix 权限为 0600。
- [ ] 密码特殊字符、userpass、IPv6、端口范围、SNI、pin、ECH、两种混淆导入后保持含义。
- [ ] `insecure=1` 在引导中默认不接受，脚本导入需要显式 `--allow-insecure`。
- [ ] 默认 doctor 没有外部连接；`--connect` 不绑定本地代理端口、不启动 TUN、不执行更新检查。
- [ ] 检查 DNS 故障、无响应 UDP、错误密码、错误 SNI/CA/pin：失败结果合理，超时不会被断言为某一种原因。
- [ ] JSON 可解析、退出码符合文档；失败输出不包含密码或完整分享链接。
- [ ] Linux SSH 终端下英文对齐、高亮正常；`NO_COLOR=1` 和重定向输出不含 ANSI 色码。
- [ ] 无参数帮助、`help server/client/service`、`--help` 排序一致，常用命令易找；help 不读取配置或启动网络。

服务端导出：

```bash
"$HY_TEST_BIN" server share -c server.yaml --address vpn.example.com:443
# userpass 认证时明确选择账号：
"$HY_TEST_BIN" server share -c server.yaml --address vpn.example.com:443 --user alice
```

- [ ] 公网/NAT 映射端口正确，不能误用 listen 的通配地址。
- [ ] 导出 → 导入 → 实际连接成功；其他用户、统计 secret、ACME Token、私钥没有进入链接。
- [ ] `--qr` 在终端可扫描；二维码和链接都按凭据保管，不放进公开问题报告。
- [ ] 外部 HTTP/command 认证通过 `--auth-stdin` 选定凭据；导出不会调用认证后端。
- [ ] 自签名 `--insecure --pin-cert` 链接能连接，错误 pin 被拒绝；注意服务器 SNI guard 仍生效。

详细说明：[CLI](cli.md)。

## 6. P1：ECH【真实线路 + 兼容性】

```bash
"$HY_TEST_BIN" ech --public-name public.example.com -o ech.pem
"$HY_TEST_BIN" ech --public-name public.example.com --retain-keys ech.pem -o ech-next.pem
# 客户端迁移后，用生成时显示的新 ID 替换下面的 NEW_ID：
"$HY_TEST_BIN" ech prune --input ech-next.pem --keep-id NEW_ID -o ech-active.pem
```

- [ ] Linux 输出文件为 0600；默认不覆盖，软链接覆盖被拒绝；输出只包含公共配置而不是私钥。
- [ ] 配置服务端 `ech.keyPath`、客户端 `tls.ech` 后，在真实网络建立连接并显示 `ECH: accepted`。
- [ ] Go 客户端 ↔ Rust 服务端、Rust 客户端 ↔ Go 服务端分别测试；普通无 ECH 客户端仍可连接。
- [ ] 重叠轮换期间新旧客户端均可连接；迁移后退役旧密钥，旧配置明确失败，新配置仍可用。
- [ ] ECH 被拒绝时无静默降级；`insecure`/内部证书 pin 不得绕过拒绝证书的严格验证。
- [ ] Linux 原生 CA 存储正常；检查自定义 CA、精简容器缺 CA 的情况。
- [ ] 轮换按“新文件 → 修改 keyPath → 重启”生效，不误认为存在热加载或自动分发。

## 7. P1：Cloudflare DNS-01 ACME【真实外部服务】

使用测试域名及范围受限的 Token，独立 ACME 缓存目录；完整配置见
[ACME DNS providers](acme-dns-providers.md)。本节会实际写入/删除 DNS TXT 并请求证书。

- [ ] `acme.type: dns`、`dns.name: cloudflare`、`cloudflare_api_token` 首次签发成功。
- [ ] Token 有目标 Zone Read / DNS Edit 权限；配置文件不是公开可读。
- [ ] 创建 `_acme-challenge` TXT、等待传播、签发和按记录 ID 清理完整执行，已有 TXT 不被误删。
- [ ] 检查普通域名、通配符（如需要）、多个域名；Token 覆盖所有目标 zone。
- [ ] 无效 Token、缺权限、错误 zone、API 不可达和传播超时均明确失败，不输出原始响应正文或 Token。
- [ ] systemd 环境下缓存路径可写，重启复用证书/账号；长期观察自动续期与挑战记录清理。
- [ ] DNS-01 无需本机 ACME TCP 80/443 验证监听；出站 DNS/HTTPS 正常。

不要为重复测试频繁请求生产 CA。当前 CLI 没有通用“任意 staging CA URL”开关；
不要直接照搬其他 ACME 工具的参数。续期未观察到之前，记录为“待长期验证”。

## 8. P1：Realm【真实 NAT，重点】

前置：准备可信的协调服务、STUN 服务及分处两端网络的设备。先关闭
`realm.portMapping.enabled`，把纯打洞和路由器映射分开测试。

```bash
# 服务端 guide 第一个问题填写 realm://TOKEN@HOST/NAME
"$HY_TEST_BIN" guide server -c realm-server.yaml
"$HY_TEST_BIN" server share -c realm-server.yaml --sni proxy.example.com
# 客户端在 guide 中粘贴生成的组合链接
"$HY_TEST_BIN" guide client -c realm-client.yaml
"$HY_TEST_BIN" doctor client --connect --timeout 30s -c realm-client.yaml
```

- [ ] `realm://` 协调服务的 HTTPS 验证正常；协调 Token 与 Hysteria 代理密码严格独立。
- [ ] STUN → 协调介绍 → UDP 打洞 → QUIC/TLS/认证各阶段结果可理解，失败后后续阶段标为跳过。
- [ ] 错误 Token、错误代理密码、失效证书、协调服务离线、STUN 无响应和打洞失败各自测试。
- [ ] 协调服务重启/断线、注册会话过期后，服务端能重新注册并接受新客户端。
- [ ] 长期空闲后重新连接；切换网络/公网地址变化后的恢复行为合理。
- [ ] 实际 TCP 和 UDP 流量可用；需要时测混淆、IPv6 与重复 STUN 参数。
- [ ] 分享链接保留 Token、`auth`、TLS、STUN；服务器本地 `lport` 不被强行分配给客户端。
- [ ] `doctor --connect` 对开启路由器映射的配置提前拒绝，不发送 UPnP/NAT-PMP 请求。

建议记录实际组合，不预设所有组合都应成功：

| 客户端网络 | 服务端网络 | STUN | 介绍 | 打洞 | TCP/UDP | 恢复 | 备注 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 公网/云主机 | 家庭宽带 NAT | 待测 | 待测 | 待测 | 待测 | 待测 | |
| 家庭宽带 A | 家庭宽带 B | 待测 | 待测 | 待测 | 待测 | 待测 | |
| 移动网络/热点 | 家庭宽带 | 待测 | 待测 | 待测 | 待测 | 待测 | |
| CGNAT | CGNAT | 待测 | 待测 | 待测 | 待测 | 待测 | 不保证成功 |
| IPv6 网络 | IPv6 网络 | 待测 | 待测 | 待测 | 待测 | 待测 | |

**P2 / 可选、会改变路由器状态**：只有你准备专门测试路由器映射时，再显式启用
UPnP/NAT-PMP，检查映射创建、续租、退出清理和失败恢复。不要与纯打洞结果混记。
Realms 没有协调服务转发流量的兜底；失败不应自动变成中继成功。

## 9. P1：状态统计与 masquerade【Linux 部署回归】

```bash
"$HY_TEST_BIN" server status -c server.yaml
"$HY_TEST_BIN" server stats --watch -c server.yaml
"$HY_TEST_BIN" server status -c server.yaml --output json
```

- [ ] 使用本机 trafficStats 地址和正确 secret 可读；错误 secret 拒绝，远端地址不会被 CLI 默认访问。
- [ ] TCP/UDP 活动数量、累计流量、速率、错误/丢包计数随实际流量变化；流量口径不是网卡总字节数。
- [ ] 旧统计清零操作不清除新的 lifetime 计数；进程重启后计数/采样正确重置。
- [ ] HTTP/2 masquerade 请求转发到 HTTP/1.1 后端正常；需要 Upgrade 的场景单独验证。
- [ ] HTTP→HTTPS 跳转：自定义端口、IPv6 Host、查询字符串正确。
- [ ] 文件模式：目录列表、缺少 index.html、名称转义、目录尾斜杠、HEAD、Range 和路径穿越拒绝。

## 10. P1/P2：TUN、透明代理及依赖升级【Linux 专项，隔离环境】

这一节是本轮依赖升级/队列改动的 Linux 回归项，**不是说刚增加了这些功能**。
涉及 tun-rs、netstack-smoltcp、Tokio/Quinn/rustls 等升级后的实际系统行为。
参考 [TUN 升级](tun-rs-upgrade.md)、[netstack 升级](netstack-upgrade.md)、
[TLS/HTTP 依赖](tls-http-dependency-upgrade.md)。

这些用例可能需要权限并修改接口、策略路由或防火墙。请在可恢复的 VM/测试机，
有控制台访问时按现有部署方法操作；此文不自动提供或执行全局路由替换命令。

- [ ] `/dev/net/tun`、设备创建/打开及权限处理正常；退出后设备/后台任务的保留或清理符合配置。
- [ ] TUN TCP、UDP、DNS、IPv4/IPv6、MTU、大包和并发转发正常；没有代理回环。
- [ ] TCP Redirect、TCP/UDP TProxy 在实际 nftables/iptables/策略路由部署下工作。
- [ ] `bindInterface`、`fwmark`、FD-control 等你实际使用的 Linux socket 选项有效；错误配置有明确错误。
- [ ] TCP Fast Open 在启用和未启用的内核环境分别检查；记录内核设置，不由测试脚本随意改 sysctl。
- [ ] 高并发 UDP/突发队列压力下，丢包不会错误地永久关闭整个转发会话；流量恢复后继续工作。
- [ ] 长时间负载观察 CPU、RSS、FD、连接/会话数量及退出后的资源回收。
- [ ] 测试结束后恢复原有接口、路由、DNS 和防火墙状态，验证 rc.6 原部署仍可用。

## 11. 验收结果模板

每个失败项建议记录一条，不上传真实 Token、完整分享链接、私钥或含凭据的配置。

```text
测试项：例如 3.1 开机自启
结果：通过 / 失败 / 未执行 / 不适用
Git 提交与工作区状态：
二进制 SHA-256：
Linux / 架构 / 内核 / systemd：
Go 对照版本（如适用）：
配置差异（脱敏）：
执行命令（脱敏）：
预期：
实际：
退出码：
相关日志（脱敏）：
复现次数：
rc.6 相同条件的结果：
```

优先顺序：**构建与普通转发 → systemd 生命周期/重启 → 客户端与分享 →
ECH/Cloudflare → Realm 真实 NAT → TUN/TProxy/压力与长期续期**。
不使用的功能可以标为“不适用”，不要用其他测试通过来替代它的验收。

## 补充：客户端分流 v1 与 GUI JSON 接口（后续新增）

这部分在初版清单之后新增，目前也需随工作区一起构建。详见
[分流配置与 GUI 契约](client-routing.md)。

- [ ] **P0**：`capabilities --output json`、`route explain ... --output json` 输出可解析、有版本且不泄露凭据；capabilities 不读取配置。
- [ ] **P0**：同一 SOCKS5 UDP 关联内的 direct/proxy/reject 互不串线；拒绝目标不关闭整个关联。
- [ ] **P0**：代理失联/握手超时时，直连 TCP/UDP 仍可用，代理请求没有静默直连兜底。
- [ ] **P1**：HTTP CONNECT、普通 HTTP、TCP/UDP forwarding 按规则选择出口。
- [ ] **P1**：实际 Linux DNS、IPv6 和长时间 UDP 压力测试，观察每关联直连流上限、队列丢包和空闲回收。
- [ ] **P0**：停止核心后，既有直连流也退出，监听端口释放。
- [ ] **P0**：配置 routing 与未配置保护的 TUN、非 Linux TUN 或 TProxy/Redirect 组合时提前拒绝；进程、GeoIP/GeoSite 等尚未支持的规则不被静默接受。
- [ ] GUI 不把“离线解释文件配置”误认为“查询正在运行的规则”；v1 还没有热更新、事件或持续 IPC 接口。


## 补充：Linux protected TUN + Fake-IP（jp1 隔离内核验收已完成）

配置及限制见 [protected TUN](client-tun-routing.md)。自动测试已覆盖缓存持久化、
双栈映射、DNS TCP framing/UDP 截断、CNAME/环检测、域名恢复后的 TCP/UDP 直连、
保护 socket 的 mark/interface、策略规则构造及 Linux 内核规则只读预检。
Docker 禁用了 NET_ADMIN；这些自动测试本身不代表实际安装路由或捕获数据包通过。
后续已在 jp1 的隔离网络命名空间验证真实 TUN，详见
[验收结果与修复](linux-tun-jp1-2026-11-11.md)。以下整机 DNS、性能等综合条目仍按未完成保留。

必须使用可恢复的隔离 Linux 环境/本地控制台，先保存接口、IPv4/IPv6 路由、
策略规则和 DNS 基线。不要在唯一 SSH 通道上首次测试。

- [ ] **P0**：缺少 egress/cache/strict、mark 为 0、排除路由、Realm、FD-control、
  冲突 socket 设置均拒绝；`check` 不创建缓存、接口或改变网络。
- [ ] **P0**：实际创建 TUN 和独立表，主表不变；已有自定义 ip rule / Fake-IP
  网段冲突时拒绝，失败启动无自身路由/规则残留。
- [ ] **P0**：A/AAAA 映射跨重启一致，TCP/UDP 恢复域名后按 direct/proxy/reject
  执行；未知 Fake-IP 不进入服务器或物理出口。
- [ ] **P0**：指定出口接口上的 QUIC、bootstrap DNS、直连 TCP/UDP 不再次进入 TUN；
  代理不可用时不回退直连，出口接口失效时不改用未保护 socket。
- [ ] **P0**：systemd-resolved 与普通 resolv.conf 分别测试；只有进入 TUN 的 DNS
  被处理，按需手工配置 per-link DNS，并记录恢复方式。测试 DoH/DoT 的明确边界。
- [ ] **P0**：SIGINT/SIGTERM、启动中途失败后检查 owned routes/rules 清理；
  隔离环境 SIGKILL 后记录残留和人工恢复步骤，验证重启拒绝未知旧规则。
  当前没有自动崩溃恢复，unreachable 残留可能阻断联网。
- [ ] **P1**：非 A/AAAA 查询的 direct/proxy/reject、TCP DNS 重试、IPv6、MTU、
  高并发 UDP、缓存满/损坏/只读/并发占用正常拒绝；检查文件权限与目录保护。
- [ ] **P1**：同机旧版 proxy-only TUN 回归；对照 rc.6 记录吞吐、CPU、内存、
  首次域名分配的落盘延迟和持续运行行为。
