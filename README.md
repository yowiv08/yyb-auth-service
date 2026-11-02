# yyb-auth-service

通过应用宝（腾讯应用宝 PC 端）的微信扫码登录获取微信账号登录态，并以该账号身份调用微信能力的 HTTP 服务。

一次扫码之后，服务会把账号的应用宝凭据（CK）和微信协议层登录态保存在本地 SQLite 中，之后调用方只需提供账号的 `unionid`，就可以：

- 获取微信用户资料（昵称、头像等）
- 获取任意小程序的登录 code
- 获取账号在小程序下绑定的手机号
- 完成公众号网页授权并拿到授权 code
- 调用小程序 `operateWXData`（云函数、云网关三元组等）
- 发送任意 Transfer 协议请求，用于调试新协议

凭据过期时服务会自动刷新；在凭据失效之前，还可以不重新扫码直接换发一套新 CK（`/api/renewck`）。

完整的接口说明见 [API.md](./API.md)，服务启动后根路径 `/` 提供 Swagger UI。

## 快速开始

需要 Go 1.26 及以上。

```bash
go run ./cmd/yyb-auth-service
```

启动后服务监听 `127.0.0.1:8080`，数据库写在当前目录的 `runtime/yyb.db`。启动日志里有两行需要留意：

```json
{"time":"…","level":"INFO","msg":"鉴权令牌已加载","token":"<这就是 Bearer Token>"}
{"time":"…","level":"INFO","msg":"HTTP服务开始监听","addr":"127.0.0.1:8080"}
```

Bearer Token 在首次启动时随机生成并保存到数据库，之后每次启动都会打印同一个值。

### 第一次扫码

1. 浏览器打开 `http://127.0.0.1:8080/`，点击右上角 `Authorize`，填入日志中的 token（不带 `Bearer ` 前缀）。
2. 展开 `POST /api/scan`，点击 `Execute`。页面会弹出二维码并自动轮询状态。
3. 用微信扫码并在手机上确认。弹窗显示"已完成"后，结果中的 `account_unionid` 就是新账号的 `unionid`。
4. 之后所有接口都用这个 `unionid` 指定账号，例如获取用户资料：

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"<account_unionid>"}' \
  http://127.0.0.1:8080/api/getuserinfo
```

不使用 Swagger UI 时，流程是：`POST /api/scan` 拿到 `qr_url` 和 `id`，把 `qr_url` 的二维码展示给用户，然后轮询 `GET /api/scan?scan_id=<id>` 直到 `status` 变为终态。

### Docker

```bash
docker build -t yyb-auth-service .
```

```bash
docker run -d --name yyb-auth-service -p 8080:8080 -v yyb-data:/data yyb-auth-service
```

镜像内服务监听 `0.0.0.0:8080`，数据库在 `/data/yyb.db`，请把 `/data` 挂载为持久卷，否则重建容器会丢失账号和 token。token 用 `docker logs yyb-auth-service` 查看。

## 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | Swagger UI（无需鉴权） |
| `GET` | `/openapi.json` | OpenAPI 3.0.3 规范（无需鉴权） |
| `POST` | `/api/scan` | 创建扫码会话，返回二维码；扫码确认后自动保存账号 |
| `GET` | `/api/scan?scan_id=1` | 查询扫码会话状态 |
| `GET` | `/api/users` | 获取全部账号，含凭据 |
| `POST` | `/api/users` | 按 `unionid` 删除账号 |
| `POST` | `/api/renewck` | 不重新扫码，为已有账号换发新的应用宝 CK |
| `POST` | `/api/getuserinfo` | 获取账号的微信用户资料（昵称、头像等） |
| `POST` | `/api/code` | 获取指定小程序的登录 code |
| `POST` | `/api/getphone` | 获取账号在指定小程序下的手机号 |
| `POST` | `/api/oauthauthorize` | 发起公众号网页授权，返回授权 code 或待确认信息 |
| `POST` | `/api/oauthconfirm` | 确认公众号网页授权并获取 code |
| `POST` | `/api/operatewxdata` | 以账号身份调用小程序 `operateWXData`（含云函数、云网关三元组） |
| `POST` | `/api/transfer` | 以账号身份发送任意 Transfer 协议请求，用于调试 |

`/api/*` 全部需要 `Authorization: Bearer <token>`。请求体、错误格式、超时和并发行为等约定见 [API.md 第 1 节](./API.md#1-通用约定)。

## 配置

全部通过环境变量配置：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `YYB_LISTEN_ADDR` | `127.0.0.1:8080`（Docker 镜像内为 `0.0.0.0:8080`） | HTTP 监听地址 |
| `YYB_RUNTIME_DIR` | `<当前目录>/runtime`（Docker 镜像内为 `/data`） | 运行数据目录 |
| `YYB_DB_PATH` | `<YYB_RUNTIME_DIR>/yyb.db` | SQLite 数据库文件路径 |
| `YYB_LOG_LEVEL` | `info` | 日志级别：`debug`、`info`、`warn`、`error` |
| `YYB_CORS_ORIGINS` | `*` | 允许的跨域来源，多个用英文逗号分隔 |

## 运维说明

- **日志**：JSON 格式输出到标准输出，时间为东八区（`Asia/Shanghai`）本地时间。每个 `/api/*` 请求结束时记录一条 `HTTP请求完成`，包含 `request_id`、`path`、`status_code`、`duration_ms`；请求头 `X-Request-ID` 会被回显并写入日志，便于对照。
- **重置 token**：删除 SQLite 中 `service_settings` 表内 `key = 'auth.bearer_token'` 的记录并重启，服务会生成新 token。
- **数据安全**：数据库和 `GET /api/users` 的响应都包含账号的 `access_token`、`refresh_token` 和微信协议密钥，启动日志中包含 Bearer Token。请把服务部署在可信网络内，妥善保管数据库文件和日志。
- **对外监听**：`YYB_LISTEN_ADDR` 改为 `0.0.0.0:<port>` 时服务会暴露到网络，务必配合网络层访问控制使用。

## 开发

```bash
make run
```

```bash
make fmt
```

目录结构：

| 目录 | 内容 |
| --- | --- |
| `cmd/yyb-auth-service` | 程序入口 |
| `internal/httpapi` | HTTP 路由、请求校验、响应组装，以及内嵌的 Swagger UI 和 `openapi.json` |
| `internal/service` | 各接口的业务流程：扫码、取码、换新 CK、公众号授权等 |
| `internal/native` | 微信长连接协议实现：mmtls、ManualAuth、JSLogin、operateWXData、Transfer 等 |
| `internal/yyb` | 应用宝 HTTP 接口客户端：扫码、OAuth、刷新凭据、微信用户资料 |
| `internal/credential` | 账号凭据管理：自动刷新、协议状态合并、同账号操作串行化 |
| `internal/store`、`internal/db` | SQLite 存储与建表 |

修改接口后请同步更新 `internal/httpapi/openapi.json` 和 [API.md](./API.md)。
