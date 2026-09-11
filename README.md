# openarrayvpn

北京大学 Array AG SSL VPN（arrayvpn.pku.edu.cn）的开源客户端替代品。
不接管系统网络栈/DNS，只在本地提供 **SOCKS5** 和 **HTTP 代理**，按服务器下发的
路由表分流：校内网段走隧道，其余流量直连。

协议流程和逆向分析见 [协议分析笔记](docs/protocol.md)。

## 编译

```sh
# 开发构建
go build -o openarrayvpn .

# 发布构建
go build -trimpath -ldflags='-s -w' -o openarrayvpn .
```

发布构建移除本地源码路径、符号表和 DWARF 调试信息，缩小分发体积，
不裁剪代理或 VPN 功能。开发构建保留调试信息；需要关闭优化和内联时，
使用 `go build -gcflags='all=-N -l' -o openarrayvpn .`。

## 使用

```sh
./openarrayvpn -u <学工号>            # 密码交互输入
OAV_USER=xxx OAV_PASS=yyy ./openarrayvpn   # 或用环境变量
```

启动后：

- SOCKS5 代理：`127.0.0.1:1080`（支持域名远端解析，经隧道 DNS）
- HTTP 代理：`127.0.0.1:1080`（CONNECT + 普通 HTTP，与 SOCKS5 共用 mixed 端口）

```sh
curl --socks5-hostname 127.0.0.1:1080 https://its.pku.edu.cn/
curl -x http://127.0.0.1:1080 https://its.pku.edu.cn/
ssh -o 'ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p' user@内网服务器
```

默认只监听一个端口。用 `-mixed 127.0.0.1:7890` 修改地址；恢复旧的双端口布局：

```sh
./openarrayvpn -mixed '' -socks 127.0.0.1:1080 -http 127.0.0.1:8080 -u <学工号>
```

独立端口为额外监听，不能与 mixed 使用同一地址。
本项目支持 SOCKS5 TCP CONNECT、HTTP 和 HTTPS CONNECT，不支持 SOCKS4 或 UDP ASSOCIATE。
默认仅绑定本机回环地址，代理入口不提供身份认证。

## 二次验证

账号被风控触发二次验证时（如频繁重登），客户端会显示服务器给出的问题
并等待输入，两种均支持：

- `4位缺位电话号码：[138****1234]` → 输入缺的 4 位
- `身份证/护照后6位` → 输入后 6 位

无人值守运行可用环境变量自动应答：

```sh
OAV_CHAL_PHONE=xxxx OAV_CHAL_ID=yyyyyy ./openarrayvpn ...
```

## 选项

运行 `./openarrayvpn --help` 查看帮助；参数支持单横线和双横线。

| 参数 | 默认 | 说明 |
|---|---|---|
| `-server` | `arrayvpn.pku.edu.cn:443` | VPN 服务器 |
| `-u` / `-p` | — | 用户名/密码（或 `OAV_USER` / `OAV_PASS`） |
| `-mixed` | `127.0.0.1:1080` | SOCKS5 + HTTP 共用监听地址，空串关闭 |
| `-socks` | 空 | 额外 SOCKS5 监听地址 |
| `-http` | 空 | 额外 HTTP 代理监听地址 |
| `-route-all` | false | 所有流量走隧道（默认仅校内网段） |
| `-ca` | — | 严格校验服务器证书的 CA bundle |
| `-insecure` | false | 完全关闭服务器证书检查 |
| `-v` | false | 打印每个 IP 包的摘要 |

## 证书校验

PKU 服务器证书由私有 CA（INFOSEC Technologies）签发，公开信任链无法验证，
官方客户端默认也不校验（`server_cert_check_on=0`）。本工具的默认策略比官方
更严：**TOFU 钉扎**——首次连接时记录服务器证书的 SHA-256 指纹到
`~/Library/Application Support/openarrayvpn/known_servers`（macOS；
Linux 为 `~/.config/openarrayvpn/known_servers`），之后每次连接比对，
证书变化即拒绝连接并报错（确属 PKU 换证书时删除该文件即可）。有 CA bundle 时用 `-ca`
做严格链校验；`-insecure` 完全关闭检查（仅限调试）。

已有证书记录读取失败或格式损坏时会拒绝连接，不会重新信任证书；
记录更新采用临时文件加原子替换，避免中断写入截断原记录。

域名优先使用隧道 DNS 的结果并尝试连接，失败后才查询系统 DNS。
每批结果都按最终 IP 重新分流，并去重；单次拨号最多 15 秒，且会按
剩余候选数分配请求剩余时间，为地址回退保留时间。系统 DNS 回退查询
最多 4 秒，并为随后的拨号预留时间。

## 局限

- 仅网络层（L3）隧道；不支持桌面门户、应用级发布等 iSecSP 高级功能
- 未实现 DTLS（PKU 服务器本身未开启）
- 仅测试过校友/学生账密 + 两类二次验证；证书/RSA 令牌等认证方式未实现
