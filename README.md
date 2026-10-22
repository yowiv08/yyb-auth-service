# yyb-auth-service

应用宝扫码登录、账号管理、微信用户资料、小程序 code、公众号网页 OAuth2 授权、手机号、operateWXData 和通用 Transfer 服务。

## 功能

| 方法 | 路径 | 功能 |
| --- | --- | --- |
| `GET` | `/` | Swagger UI |
| `GET` | `/openapi.json` | OpenAPI 规范 |
| `GET` | `/api/users` | 获取账号列表，按首次入库顺序固定返回 |
| `POST` | `/api/users` | 删除账号，保留扫码历史 |
| `POST` | `/api/getuserinfo` | 获取微信 OAuth 用户资料 |
| `POST` | `/api/code` | 获取单个小程序 appid 的 code |
| `POST` | `/api/operatewxdata` | 调用 operateWXData、云函数或获取云网关三元组 |
| `POST` | `/api/getphone` | 获取手机号 |
| `POST` | `/api/oauthauthorize` | 提交公众号网页授权请求，返回授权状态或 code |
| `POST` | `/api/oauthconfirm` | 确认公众号网页授权并获取 code |
| `POST` | `/api/transfer` | 通用 Transfer 协议调试 |
| `POST` | `/api/scan` | 创建扫码会话，返回二维码并自动更新扫码状态 |
| `GET` | `/api/scan?scan_id=1` | 查询扫码会话状态 |

扫码确认后保存或更新账号。Swagger UI 会自动显示二维码和最终扫码状态。

账号使用 `unionid` 标识。账号列表按首次入库顺序返回，更新凭据和重扫同一账号不改变顺序，新账号追加在末尾。

时间间隔使用 `H` 小时、`M` 分钟、`S` 秒文本，省略为 0 的单位，`duration` 最小 `1S`。扫码剩余时间到期后为 `0S`。

## 小程序 code

`POST /api/code` 接受 `unionid`、单个字符串 `appid` 和必填 `type`：

- `1`：标准取码。
- `2`：快速取码。

## operateWXData

`POST /api/operatewxdata` 支持三种模式：

- `type=1`：raw 模式，提供完整 `operateWXData.data`。
- `type=2`：云函数快捷模式，提供 `function_name` 和云函数入参 `data`。
- `type=3`：云网关三元组模式，返回 `token/key/rid`，`data` 可传空对象。

## 通用 Transfer

`POST /api/transfer` 可指定 `cgi`、`route`、请求体和响应解码方式，默认 `route=1029`。

- `inner_mode`：`standard`、`protobuf` 或 `raw`。
- `data_format`：`none`、`json`、`text` 或 `base64`。
- `response_mode`：`auto`、`json`、`protobuf` 或 `raw`。
- `outer` 和 `transport`：覆盖信封和传输参数。
- 返回解码内容、响应明文、请求信息和响应信息。

完整参数和响应见 [API.md](./API.md)。

## 鉴权与配置

`/api/*` 需要 `Authorization: Bearer <token>`；`/` 和 `/openapi.json` 公开。Swagger UI 的 `Authorize` 填写 token 本体。

Bearer Token 自动生成并保存到 SQLite，启动日志显示当前 token。日志使用 JSON 格式，保留原始内容。

| 变量 | 默认值 | 功能 |
| --- | --- | --- |
| `YYB_LISTEN_ADDR` | 本地 `127.0.0.1:8080`；Docker `0.0.0.0:8080` | HTTP 监听地址 |
| `YYB_RUNTIME_DIR` | 本地 `runtime`；Docker `/data` | 运行数据目录 |
| `YYB_DB_PATH` | `${YYB_RUNTIME_DIR}/yyb.db` | SQLite 数据库路径 |
| `YYB_LOG_LEVEL` | `info` | 日志级别：`debug`、`info`、`warn`、`error` |
| `YYB_CORS_ORIGINS` | `*` | 允许跨域来源，多个来源用英文逗号分隔 |
