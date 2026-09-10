# openarrayvpn

北京大学 Array AG SSL VPN（arrayvpn.pku.edu.cn）的开源客户端替代品。
不接管系统网络栈/DNS，只在本地提供 **SOCKS5** 和 **HTTP 代理**，按服务器下发的
路由表分流：校内网段走隧道，其余流量直连。

协议实现基于对官方客户端（iSecSP / MotionPro，Array Networks AG 系列）的分析，
隧道部分与 OpenConnect 的 `array.c` 一致（PKU 服务器未启用 DTLS 加速隧道，
纯 TLS 通道即可）。

## 编译

```sh
go build -o openarrayvpn .
```

## 使用

```sh
./openarrayvpn -u <学工号>            # 密码交互输入
OAV_USER=xxx OAV_PASS=yyy ./openarrayvpn   # 或用环境变量
```

启动后：

- SOCKS5 代理：`127.0.0.1:1080`（支持域名远端解析，经隧道 DNS）
- HTTP 代理：`127.0.0.1:8080`（CONNECT + 普通 HTTP）

```sh
curl --socks5-hostname 127.0.0.1:1080 https://its.pku.edu.cn/
curl -x http://127.0.0.1:8080 https://its.pku.edu.cn/
```

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

| 参数 | 默认 | 说明 |
|---|---|---|
| `-server` | `arrayvpn.pku.edu.cn:443` | VPN 服务器 |
| `-u` / `-p` | — | 用户名/密码（或 `OAV_USER` / `OAV_PASS`） |
| `-socks` | `127.0.0.1:1080` | SOCKS5 监听地址，空串关闭 |
| `-http` | `127.0.0.1:8080` | HTTP 代理监听地址，空串关闭 |
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

## 协议笔记（arrayvpn.pku.edu.cn, Rel.AG-HG-K.10.3.0.18）

PKU 已验证的核心 L3 流程与官方实现基本对应（经 Ghidra 反编译
`vl3vpn.dylib` 交叉核对），但仍有差异，见本节末尾。

1. `GET /prx/000/http/localhost/login` → 获得匿名会话 cookie `ANsession*=VPN`
2. `GET /prx/000/http/localhost/an_login.js` → AAA 方式列表（PKU 为 `北京大学VPN`/Radius）
3. `POST /prx/000/http/localhost/login`，表单
   `method/uname/pwd/pwd1/pwd2/deviceid/device_name/hardwareid/customer1`
   - 成功：302 → `/welcome`，`ANsession*=VPN+<id>_<hash>`
   - 失败：`_AN_msgStr` cookie 里是 URL 编码的错误信息
   - 二次验证：302 → `/challenge`；问题文本在 `_AN_str_info_chal`
     （官方客户端直接解析 `GET /prx/000/http/localhost/challenge` 响应，
     本实现亦优先如此，拿不到再取页面引用的 `an_chal.js`），把答案作为
     `pwd` POST 到 `/prx/000/http/localhost/challenge`
4. `GET /prx/000/http/localhost/vpntunnel`（头：`appid: SSPVPN`, `clientid`,
   `cpuid`, `hostname`, `payload-ip-version: 6`, `x-devtype: 6`）。
   **201 才进入 JSON 配置协议**；200 是旧二进制配置协议，本实现明确拒绝
5. 发 `conf50`（16B）→ 收 16B 头（首字节须为 `0x51`）+ JSON
   （`keepalive_interval`，`allow_speed_tunnel=0` 即无 DTLS）；
   发 `conf54`（48B：本机 IPv4 列表与 MAC 动态填写）→ 响应首字节须为
   `0x55`，JSON 配置（`client_ipv4`/掩码/DNS/路由表/`resource_group_flag`，
   IPv4 地址为小端序整数编码）；JSON 长度在响应头第 12–15 字节
   （小端序），末尾可能有 NUL 填充
6. `resource_group_flag & 1` 为服务器下发的全隧道模式：开启时所有 IPv4
   走隧道（exclude 列表除外），IPv6 因隧道仅配置 IPv4 而明确拒绝
7. 数据面：TLS 流承载裸 IPv4 包（可能跨记录拆分/合包）；`proto=0xff`
   为控制包，第 12-13 字节（大端）为命令字：
   - cmd 1 = keepalive：只记录，**不应答**（服务器会反射 DPD，回显会造成
     乒乓风暴）——这一点与官方 `handle_atp_packets` 一致；保活调度/超时
     细节（空闲即发、4 倍间隔判死）是本项目的策略
   - cmd 2 = KILL_TUNNEL：第 16-19 字节大端为原因码（1=账号它处登录，
     2=会话无效，3=会话过期，8=登出，0xe=同 clientid 第二会话）。
     官方按原因分别处理，本项目策略是一律重连重登
8. 登出：`GET /prx/000/http/localhost/logout`

已知差异：官方请求带 `ANStandalone=true;SPA-Session=...` cookie，本实现
不带（PKU 实测不需要）；`/vpntunnel` 短路径在 PKU 也可用，但本实现按
官方使用完整路径。

## 局限

- 仅网络层（L3）隧道；不支持桌面门户、应用级发布等 iSecSP 高级功能
- 未实现 DTLS（PKU 服务器本身未开启）
- 仅测试过校友/学生账密 + 两类二次验证；证书/RSA 令牌等认证方式未实现

`probe/` 目录是协议分析用的 Python 一次性脚本，`pkgs/` 是官方安装包（不入库）。
