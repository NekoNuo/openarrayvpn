# 协议分析笔记

协议实现基于对官方客户端（iSecSP / MotionPro，Array Networks AG 系列）的分析，
隧道部分与 OpenConnect 的 `array.c` 一致（PKU 服务器未启用 DTLS 加速隧道，
纯 TLS 通道即可）。

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

2026-09-11 的实际登录与欢迎页响应未下发 `role_names` cookie；
角色是可选元数据，不作为登录成功的必要条件。

## Mixed 代理实现参考

mixed 采用
[Mihomo](https://github.com/MetaCubeX/mihomo/blob/Meta/listener/mixed/mixed.go) 和
[sing-box](https://github.com/SagerNet/sing-box/blob/testing/protocol/mixed/inbound.go)
的首字节识别思路：`Peek(1)` 检测 SOCKS5，其余交给 HTTP 解析，复用同一缓冲读取器。

## 分析材料

`probe/` 目录是协议分析用的 Python 一次性脚本，`pkgs/` 是官方安装包（不入库）。
