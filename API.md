# yyb-auth-service 接口文档

## 基本说明

- 默认监听地址：`127.0.0.1:8080`
- 数据格式：`application/json; charset=utf-8`
- JSON 请求体只接受一个完整值，拒绝尾随 JSON 或垃圾内容；请求体上限为 16 MiB。
- Swagger UI：`GET /`
- OpenAPI 规范：`GET /openapi.json`
- 时间间隔字段使用 `H` 小时 / `M` 分钟 / `S` 秒文本，省略为 0 的单位；整秒截断，`duration` 最小 `1S`，例如 `32H24M38S`。扫码剩余时间到期后为 `0S`
- `/api/*` 接口需要 Bearer Token
- 默认允许跨域请求，可用 `YYB_CORS_ORIGINS` 覆盖，多个来源用英文逗号分隔
- 用户唯一标识是 `unionid`
- `scan_id` 是本机数据库里的扫码会话自增 ID，不保证跨机器一致

鉴权方式：

```http
Authorization: Bearer <token>
```

说明：

- `/` 和 `/openapi.json` 不需要 token。
- Swagger UI 的 `Authorize` 中只填写 token 本体，不需要填写 `Bearer` 前缀。
- token 启动时从 SQLite 读取；如果不存在或为空，服务会自动生成并保存。
- 每次启动都会在日志中打印当前 token。
- 需要重置时，删除 SQLite 中 `service_settings` 表内 `key='auth.bearer_token'` 的记录，然后重启服务。

通用错误返回：

```json
{
  "error": "错误信息"
}
```

## 接口列表

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | Swagger UI |
| `GET` | `/openapi.json` | OpenAPI 3.0.3 JSON |
| `GET` | `/api/users` | 获取全部用户 |
| `POST` | `/api/users` | 删除账号 |
| `POST` | `/api/getuserinfo` | 获取已授权账号的微信 OAuth 用户资料 |
| `POST` | `/api/code` | 同步获取单个 appid 的小程序 code |
| `POST` | `/api/operatewxdata` | 代请求小程序 `operateWXData`、云函数或云网关三元组 |
| `POST` | `/api/getphone` | 获取手机号 |
| `POST` | `/api/oauthauthorize` | 提交公众号网页授权请求，返回授权状态或 code |
| `POST` | `/api/oauthconfirm` | 确认公众号网页授权并获取 code |
| `POST` | `/api/transfer` | 通用 Transfer 协议调试 |
| `POST` | `/api/scan` | 创建扫码会话并启动后台自动轮询 |
| `GET` | `/api/scan?scan_id=1` | 查询扫码会话状态 |

## 主要数据结构

### User

```json
{
  "unionid": "o_xxx",
  "openid": "o_xxx",
  "guid": "xxx",
  "login_type": "WX",
  "access_token": "xxx",
  "refresh_token": "xxx",
  "wx_code": "xxx",
  "state": "xxx",
  "device_id_b64": "xxx",
  "app_device_id": "xxx",
  "username": "xxx",
  "uin": "xxx",
  "autoauth_key_b64": "xxx",
  "autoauth_enc_key_b64": "xxx",
  "ck_expires_at": "Mon, 27 Jul 2026 10:14:30 GMT",
  "duration": "1S"
}
```

说明：

- 账号列表按首次入库顺序固定返回，更新凭据和重扫同一账号不改变顺序，新账号追加在末尾。
- `ck_expires_at` 来自应用宝 OAuth `Set-Cookie` 里的 `Expires` 字符串。
- `duration` 是账号记录从创建到最近更新的间隔，使用 H/M/S 时间文本，最小 1S。

### UserInfo

```json
{
  "ok": true,
  "unionid": "o_xxx",
  "openid": "o_xxx",
  "nickname": "昵称",
  "headimgurl": "https://thirdwx.qlogo.cn/...",
  "sex": 0,
  "country": "",
  "province": "",
  "city": "",
  "privilege": [],
  "duration": "1S"
}
```

说明：

- 该接口返回微信 OAuth `sns/userinfo` 用户资料，不是小程序 `wx.getUserInfo` 的 `nickName/avatarUrl` 字段形态。
- `nickname` 是微信资料昵称。
- `headimgurl` 是微信头像 URL。
- 微信业务失败时仍返回 `200 OK`，`ok=false`，并带 `errcode/errmsg`。

### CodeResult

```json
{
  "unionid": "o_xxx",
  "appid": "wx7c45a544886d9e69",
  "type": 1,
  "status": "succeeded",
  "code": "081xxx",
  "error": "",
  "duration": "25S"
}
```

`status` 可能值：

- `succeeded`
- `failed`

### ScanSession

```json
{
  "id": 1,
  "status": "waiting",
  "guid": "xxx",
  "state": "xxx",
  "uuid": "xxx",
  "qr_url": "https://open.weixin.qq.com/...",
  "scan_expires_in": "2M",
  "last_errcode": "",
  "wx_code": "",
  "openid": "",
  "unionid": "",
  "account_unionid": "",
  "ck_expires_at": "",
  "error": "",
  "duration": "1S"
}
```

`status` 可能值：

- `waiting`：等待扫码
- `scanned`：已扫码，待确认
- `authorized`：已确认，账号处理中
- `completed`：账号已保存或更新
- `canceled`：用户取消
- `expired`：扫码会话过期
- `failed`：接口调用失败或入库失败

## 请求方式

### 获取用户列表

```bash
curl -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8080/api/users
```

成功返回：`200 OK`，返回 `User[]`。

说明：

- 按首次入库顺序固定返回，凭据刷新和重扫同一账号不会改变顺序，新账号追加在末尾。
- 当前没有分页。
- 调用方可从列表中按 `unionid` 筛选。

### 删除用户

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"unionid\":\"o_xxx\"}" \
  http://127.0.0.1:8080/api/users
```

请求体：

```json
{
  "unionid": "o_xxx"
}
```

成功返回：`200 OK`。

```json
{
  "ok": true,
  "unionid": "o_xxx",
  "deleted": true,
  "detached_scan_sessions": 3
}
```

说明：

- `unionid` 必填。
- 删除账号时保留扫码历史，并解除账号关联。
- `detached_scan_sessions` 是本次解除账号关联的扫码历史数量。
- 账号不存在时返回 `404 Not Found`。

### 获取用户资料

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"unionid\":\"o_xxx\",\"lang\":\"zh_CN\"}" \
  http://127.0.0.1:8080/api/getuserinfo
```

请求体：

```json
{
  "unionid": "o_xxx",
  "lang": "zh_CN"
}
```

规则：

- `unionid` 必填。
- `lang` 可选，默认 `zh_CN`，只允许 `zh_CN`、`zh_TW` 或 `en`。
- 按 `unionid` 获取微信 OAuth 用户资料。
- `access_token` 不作为请求参数。

成功返回：`200 OK`，返回 `UserInfo`。

常见失败：

- `400 Bad Request`：`unionid` 缺失。
- `400 Bad Request`：`lang` 不在允许范围内。
- `400 Bad Request`：本地账号库中不存在对应 `unionid`。
- `400 Bad Request`：账号存在，但本地记录缺少 `openid` 或 `access_token`。
- `200 OK + ok=false`：微信返回业务错误，错误码在 `errcode/errmsg` 字段。

### 公众号 OAuth2 授权并获取 code

公众号网页授权接口：

```text
POST /api/oauthauthorize
POST /api/oauthconfirm
```

`POST /api/oauthauthorize` 请求体：

```json
{
  "unionid": "o_xxx",
  "appid": "wx1234567890abcdef",
  "redirect_uri": "https://example.com/oauth/callback",
  "scope": "snsapi_userinfo",
  "state": ""
}
```

`scope` 仅支持 `snsapi_base` 和 `snsapi_userinfo`。`state` 为空时由服务端生成。成功时返回 `status=confirmation_required` 和 `authorization_url`；如果上游已直接返回授权 code，则返回 `status=completed` 和 `code`。

`POST /api/oauthconfirm` 请求体：

```json
{
  "unionid": "o_xxx",
  "appid": "wx1234567890abcdef",
  "authorization_url": "https://open.weixin.qq.com/connect/oauth2/authorize?...",
  "avatar_id": "0"
}
```

`avatar_id` 是授权响应 `avatar_list[].id` 中的非负整数文本；省略时使用 `0`。

成功返回：

```json
{
  "status": "completed",
  "unionid": "o_xxx",
  "appid": "wx1234567890abcdef",
  "code": "公众号网页授权CODE",
  "state": "STATE",
  "redirect_uri": "https://example.com/oauth/callback",
  "duration": "1S"
}
```

账号标识使用 `unionid`。接口返回公众号网页授权 code。请求参数错误返回 `400`，账号不存在返回 `404`，微信业务拒绝返回 `422`，上游协议错误返回 `502`，超时返回 `504`。

### 同步获取小程序 code

标准取码：

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"unionid\":\"o_xxx\",\"appid\":\"wx7c45a544886d9e69\",\"type\":1}" \
  http://127.0.0.1:8080/api/code
```

快速取码：

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"unionid\":\"o_xxx\",\"appid\":\"wx7c45a544886d9e69\",\"type\":2}" \
  http://127.0.0.1:8080/api/code
```

请求体：

```json
{
  "unionid": "o_xxx",
  "appid": "wx7c45a544886d9e69",
  "type": 1
}
```

规则：

- `unionid` 必填。
- `appid` 必填，且只支持单个字符串。
- `type` 必填，只允许 `1` 或 `2`。
- `type=1`：标准取码。
- `type=2`：快速取码。
- 多个 `appid` 请顺序多次请求 `/api/code`。

成功返回：`200 OK`，返回 `CodeResult`。上游失败时返回 `200 OK + status=failed`，错误信息在 `error` 字段。

常见失败：

- `400 Bad Request`：`unionid`、`appid` 或 `type` 缺失。
- `400 Bad Request`：`type` 不是 `1` 或 `2`。
- `400 Bad Request`：用户不存在。
- `type=2` 常见上游错误：`-109` 表示 appid 无效，`-105` 表示当前会话不可用，错误信息返回在 `error` 字段。

### 通用 operateWXData 代请求

raw 模式：

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"unionid\":\"o_xxx\",\"appid\":\"wx887bf6ad752ca2f3\",\"type\":1,\"operate_code\":1,\"data\":{\"api_name\":\"qbase_commapi\",\"data\":{},\"operate_directly\":false}}" \
  http://127.0.0.1:8080/api/operatewxdata
```

云函数快捷模式：

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"unionid\":\"o_xxx\",\"appid\":\"wx887bf6ad752ca2f3\",\"type\":2,\"operate_code\":1,\"function_name\":\"rsa\",\"data\":{\"score\":\"350|1782791141326\"}}" \
  http://127.0.0.1:8080/api/operatewxdata
```

云网关三元组模式：

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"unionid\":\"o_xxx\",\"appid\":\"wxde7e5cd3f013ff7d\",\"type\":3,\"operate_code\":1,\"data\":{}}" \
  http://127.0.0.1:8080/api/operatewxdata
```

规则：

- `unionid` 必填。
- `appid` 必填。
- `type` 必填，只允许 `1`、`2` 或 `3`。
- `operate_code` 可选，默认值是 `1`，必须大于或等于 `0`。
- `data` 必填。
- `type=1`：raw 模式，调用方传完整 `operateWXData.data`。
- `type=2`：云函数快捷模式，`function_name` 必填，`data` 是云函数业务入参。
- `type=3`：云网关三元组模式，返回 `token/key/rid`；`data` 可传空对象。
- `type=1` 和 `type=2` 的 `data` 为对象或数组时压缩为 JSON 字符串，为字符串时原样发送。

`type=3` 的 `data` 可选覆盖 `system`、`wx_app_version`、`scene`、`sdk_version`、`env`、`session_id`、`cli_req_id`、`rid`、`rv`，不接受 `domain`。

成功返回：`200 OK`。

```json
{
  "ok": true,
  "appid": "wx887bf6ad752ca2f3",
  "operate_code": 1,
  "duration": "1S",
  "request": {
    "cmdid": 2881,
    "cgi": "/cgi-bin/mmbiz-bin/js-operatewxdata",
    "wrapper_len": 762,
    "out_body_len": 623,
    "pack_round_trip_ok": true
  },
  "response": {
    "source": "longlinkPack",
    "task_id": 2881,
    "tag4": 0,
    "tag23": 0,
    "body_len": 663,
    "decode_mode": "raw89-sessionField2",
    "plain_len": 684
  },
  "gateway_service_info": {
    "ok": true,
    "token": "105_xxx",
    "key": "base64_aes_key",
    "rid": 1809301331,
    "qbase_rid": "7d594a9c78ffbdf0-1783614507482-661580ae1d27f820",
    "client_kx": "<客户端 X25519 公钥>",
    "server_kx": "<服务端 X25519 公钥>",
    "source": "tcbapi_get_service_info"
  },
  "decoded": {
    "err_no": 0
  },
  "decoded_raw": "{\"data\":\"...\",\"err_no\":0}"
}
```

### 获取手机号

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"unionid\":\"o_xxx\",\"appid\":\"wxde7e5cd3f013ff7d\"}" \
  http://127.0.0.1:8080/api/getphone
```

参数：

- `unionid` 必填。
- `appid` 必填，目标小程序 appid。

返回：

```json
{
  "ok": true,
  "mobile": "xxx",
  "show_mobile": "xxx",
  "encryptedData": "xxx",
  "iv": "xxx",
  "code": "xxx",
  "data": "{\"code\":\"xxx\"}",
  "duration": "2S"
}
```

字段：

- `ok`：是否拿到真实手机号（`mobile` 非空）。
- `mobile`：真实手机号。
- `show_mobile`：脱敏手机号。
- `encryptedData` / `iv`：手机号按钮回调中的加密载荷。
- `code`：从 `data` 中提取出的 code。
- `data`：`wx_phone.data` 原始 JSON 字符串。
- `duration`：本次取号耗时，使用 H/M/S 时间文本，最小 1S。
- `error`：协议或上游错误；成功时为空。

常见失败：

- `400 Bad Request`：`unionid` 或 `appid` 缺失。
- `400 Bad Request`：本地账号库中不存在对应 `unionid`。
- `400 Bad Request`：账号存在，但本地记录缺少 `openid`。
- `200 OK + error`：上游协议失败，错误信息在 `error` 字段。

### 通用 Transfer

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"unionid\":\"o_xxx\",\"appid\":\"wx887bf6ad752ca2f3\",\"cgi\":\"/cgi-bin/example\",\"route\":1029,\"data_format\":\"json\",\"data\":{\"key\":\"value\"}}" \
  http://127.0.0.1:8080/api/transfer
```

通过 `cgi`、`route`、请求体和响应解码方式调用 Transfer，`route` 默认 `1029`。

请求参数：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `unionid` | 是 | 账号唯一标识 |
| `appid` | 是 | 目标 appid，写入外层信封字段 6 |
| `cgi` | 是 | 必须以 `/` 开头的相对路径，不能带 scheme、host、userinfo 或 fragment，长度上限 2048 |
| `route` | 否 | 外层信封 route，默认 `1029` |
| `data_format` | 否 | `none`、`json`、`text` 或 `base64`，默认 `none`，仅 `standard` inner_mode 可用 |
| `data` | 否 | `json` 时为任意 JSON（压缩为 JSON 字符串）；`text` 和 `base64` 时必须是 JSON 字符串 |
| `inner_mode` | 否 | `standard`、`protobuf` 或 `raw`，默认 `standard` |
| `inner_fields` | 否 | `protobuf` 模式必填，最多 256 个字段 |
| `inner_base64` | 否 | `raw` 模式必填，标准 base64 编码的完整 inner body |
| `outer` | 否 | 外层信封覆盖，见下 |
| `transport` | 否 | 长连接传输层覆盖，见下 |
| `response_mode` | 否 | `auto`、`json`、`protobuf` 或 `raw`，默认 `auto` |

三种 `inner_mode`：

- `standard`：包含 `1=session_base`、`2=target_appid`、`3=data`（`data` 省略时不写字段 3）。不接受 `inner_fields` 和 `inner_base64`。
- `protobuf`：由 `inner_fields` 逐字段构造。不接受 `data_format`、`data` 和 `inner_base64`。
- `raw`：直接使用 `inner_base64` 解码后的字节作为 inner body。不接受 `data_format`、`data` 和 `inner_fields`。

`inner_fields[]` 的 `type` 取值：

- 模板类型 `session_base`、`target_appid`、`host_appid`、`ilink_appid`：值由服务端填充，不接受 `value` 和 `uint`。
- `string`：需要 `value`，按 UTF-8 写入。
- `bytes`：需要 `value`，必须是标准 base64。
- `varint`、`fixed32`、`fixed64`：需要 `uint`，不接受 `value`。

`number` 必须在 1 到 536870911 之间，且不能落在 protobuf 保留段 19000-19999。

`outer` 可覆盖 `host_appid`（上限 128 字符）、`field4`、`field8`、`plugin`（上限 256 字符）和 `field10`；省略的字段使用服务端内置默认值。

`transport` 可覆盖 `sequence`（默认 `4`）、`task_id`（默认 `2881`）、`task_type`（默认 `2`）和 `identity_mode`（`account` 或 `zero`，默认 `account`）。`sequence` 和 `task_id` 传 `0` 会被拒绝。

成功返回：`200 OK`。

```json
{
  "ok": true,
  "unionid": "o_xxx",
  "appid": "wx887bf6ad752ca2f3",
  "cgi": "/cgi-bin/example",
  "route": 1029,
  "data_format": "json",
  "inner_mode": "standard",
  "response_mode": "auto",
  "decoded": {},
  "decoded_format": "json",
  "decoded_raw": "{}",
  "plain_base64": "xxx",
  "request": {
    "cgi": "/cgi-bin/example",
    "route": 1029,
    "sequence": 4,
    "task_id": 2881,
    "task_type": 2,
    "identity_mode": "account",
    "inner_mode": "standard",
    "inner_body_len": 128,
    "host_appid": "wxd44977328b36e647",
    "wrapper_len": 762,
    "out_body_len": 623,
    "pack_round_trip_ok": true
  },
  "response": {
    "source": "longlinkPack",
    "task_id": 2881,
    "tag4": 0,
    "tag23": 0,
    "body_len": 663,
    "decode_mode": "raw89-sessionField2",
    "plain_len": 684
  },
  "duration": "1S"
}
```

字段：

- `decoded_format`：`json`、`protobuf` 或 `raw`。
- `ok=true` 表示 Transfer 响应成功解码；使用 protobuf 时仍需检查业务层 BaseResponse 的返回码。
- `decoded`：`json` 时是解析后的 JSON；`protobuf` 时是结构化字段树，含 `fields`、`strings` 和 `code_candidates`；`raw` 时为 `null`。
- `decoded_raw`：`json` 时是原始 JSON 文本，其余为空。
- `plain_base64`：解密后的响应明文，标准 base64 编码。
- `response.decode_mode`：`raw89-sessionField2`、`raw89-sessionField3`、`raw89-packrequest` 或 `direct-proto`。

JSON 解码接受任意合法 JSON。

常见失败：

- `400 Bad Request`：参数缺失或校验不通过。
- `404 Not Found`：`unionid` 对应账号不存在。
- `502 Bad Gateway`：上游协议错误。
- `504 Gateway Timeout`：超过 75 秒未返回。

### 创建扫码会话

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8080/api/scan
```

说明：

- 创建一次新的微信扫码登录会话。
- 返回二维码 URL 和本地 `scan_id`。
- 自动更新扫码状态。
- Swagger UI 中执行该接口时，页面会自动弹出二维码并轮询状态；扫码完成、取消、过期或失败后会在弹窗中显示最终 `ScanSession` 响应。
- 确认授权后保存或更新账号。
- 扫码会话有效期为 2 分钟。

### 查询扫码会话

```bash
curl -H "Authorization: Bearer <token>" \
  "http://127.0.0.1:8080/api/scan?scan_id=1"
```

常见失败：

- `400 Bad Request`：`scan_id` 缺失或非法。
- `404 Not Found`：会话不存在。
