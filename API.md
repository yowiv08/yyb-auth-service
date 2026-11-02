# yyb-auth-service 接口文档

本文描述 yyb-auth-service 的全部 HTTP 接口。服务的定位、部署和配置见 [README.md](./README.md)；可交互的在线文档见服务根路径的 Swagger UI（`GET /`）。

## 目录

- [1. 通用约定](#1-通用约定)
  - [1.1 基础信息](#11-基础信息)
  - [1.2 鉴权](#12-鉴权)
  - [1.3 账号与 unionid](#13-账号与-unionid)
  - [1.4 时长字段](#14-时长字段)
  - [1.5 错误返回](#15-错误返回)
  - [1.6 并发、超时与凭据刷新](#16-并发超时与凭据刷新)
- [2. 接口一览](#2-接口一览)
- [3. 扫码登录](#3-扫码登录)
  - [POST /api/scan 创建扫码会话](#post-apiscan-创建扫码会话)
  - [GET /api/scan 查询扫码会话](#get-apiscan-查询扫码会话)
  - [ScanSession 对象](#scansession-对象)
- [4. 账号管理](#4-账号管理)
  - [GET /api/users 获取账号列表](#get-apiusers-获取账号列表)
  - [POST /api/users 删除账号](#post-apiusers-删除账号)
  - [POST /api/renewck 换发应用宝 CK](#post-apirenewck-换发应用宝-ck)
  - [User 对象](#user-对象)
- [5. 微信能力](#5-微信能力)
  - [POST /api/getuserinfo 获取微信用户资料](#post-apigetuserinfo-获取微信用户资料)
  - [POST /api/code 获取小程序 code](#post-apicode-获取小程序-code)
  - [POST /api/getphone 获取手机号](#post-apigetphone-获取手机号)
  - [POST /api/oauthauthorize 发起公众号网页授权](#post-apioauthauthorize-发起公众号网页授权)
  - [POST /api/oauthconfirm 确认公众号网页授权](#post-apioauthconfirm-确认公众号网页授权)
- [6. 协议调试](#6-协议调试)
  - [POST /api/operatewxdata 调用 operateWXData](#post-apioperatewxdata-调用-operatewxdata)
  - [POST /api/transfer 通用 Transfer 请求](#post-apitransfer-通用-transfer-请求)

## 1. 通用约定

### 1.1 基础信息

| 项目 | 说明 |
| --- | --- |
| 基础地址 | 默认 `http://127.0.0.1:8080`，由环境变量 `YYB_LISTEN_ADDR` 决定 |
| 请求格式 | 所有 `POST` 接口使用 JSON 请求体，`Content-Type: application/json` |
| 响应格式 | 一律返回 `application/json; charset=utf-8` |
| 请求体限制 | 最大 16 MiB；必须恰好是一个 JSON 值；不接受未定义的字段；不接受尾随内容 |
| 跨域 | 默认允许任意来源，可用 `YYB_CORS_ORIGINS` 限制；允许 `GET`、`POST`、`OPTIONS` |
| 请求标识 | 响应头 `X-Request-ID` 回显请求头中的同名值，未提供时由服务生成，可用于在日志中定位请求 |
| 在线文档 | `GET /` 是 Swagger UI，`GET /openapi.json` 是 OpenAPI 3.0.3 规范 |

### 1.2 鉴权

除 `GET /` 和 `GET /openapi.json` 外，所有 `/api/*` 接口都需要 Bearer Token：

```http
Authorization: Bearer <token>
```

- token 在服务首次启动时随机生成并保存到 SQLite；之后每次启动都会在日志中打印（`"msg":"鉴权令牌已加载"`）。
- 鉴权失败返回 `401`，响应体为 `{"error": "缺少或无效的 Bearer Token"}`，并带 `WWW-Authenticate: Bearer` 头。
- 在 Swagger UI 中点击 `Authorize`，只填写 token 本体，不要带 `Bearer ` 前缀。
- 需要重置 token 时，删除 SQLite 中 `service_settings` 表内 `key = 'auth.bearer_token'` 的记录，然后重启服务。

### 1.3 账号与 unionid

服务中的"账号"指一个微信账号在应用宝侧的登录态：扫码登录成功后，应用宝签发的 `access_token` / `refresh_token`（下文统称 **CK**）以及微信协议层的设备和会话信息都会保存到本地 SQLite。

- 账号以微信 `unionid` 唯一标识。所有需要指定账号的接口都通过 `unionid` 参数选择账号，`unionid` 可从 `GET /api/users` 或扫码会话的 `account_unionid` 得到。
- 同一个微信账号重复扫码不会产生新账号，只会更新该账号的凭据。
- `scan_id` 是本机数据库中扫码会话的自增 ID，只在本机有意义。

### 1.4 时长字段

`duration`、`scan_expires_in` 等时长字段是形如 `1H2M3S` 的文本：按小时 `H`、分钟 `M`、秒 `S` 依次拼接，值为 0 的单位省略，不足 1 秒的部分截断。

- 表示耗时的字段最小为 `1S`，例如 `1S`、`25S`、`2M3S`、`32H24M38S`。
- `scan_expires_in` 表示剩余时间，到期或会话结束后为 `0S`。

### 1.5 错误返回

根据接口不同，错误有三种形态：

**通用错误**（大多数接口）：

```json
{
  "error": "错误信息"
}
```

**结构化错误**（`/api/oauthauthorize`、`/api/oauthconfirm`）：

```json
{
  "error": {
    "code": "OAUTH_BUSINESS_REJECTED",
    "message": "微信公众号授权失败",
    "wechat_ret": -1,
    "wechat_message": "上游返回的错误描述"
  }
}
```

**带状态的错误**（`/api/renewck`）：返回与成功响应相同结构的对象，`ok=false`，失败原因在 `error.code`、`error.stage`、`error.message` 中。

另外，下面几个接口在上游业务失败时仍返回 `200`，失败信息放在响应体中，调用方必须检查对应字段：

| 接口 | 失败表现 |
| --- | --- |
| `POST /api/code` | `status=failed`，原因在 `error` |
| `POST /api/getuserinfo` | `ok=false`，微信错误码在 `errcode` / `errmsg` |
| `POST /api/getphone` | `ok=false`，原因在 `error` |
| `GET /api/scan` | `status=failed`，原因在 `error` |

HTTP 状态码的总体约定：

| 状态码 | 含义 |
| --- | --- |
| `400` | 请求体或参数不合法，或账号记录缺少本次调用所需的字段 |
| `401` | 缺少或错误的 Bearer Token |
| `404` | 账号或扫码会话不存在 |
| `405` | 请求方法不支持，响应体为 `{"error": "仅支持 POST"}` 之类的提示 |
| `409` / `422` / `500` | 只有部分接口使用，含义见各接口的"失败"小节 |
| `502` | 协议调用或上游请求失败，以及未归类的服务端错误 |
| `504` | 超过接口的超时上限，包括等待同账号前一个操作的时间 |

### 1.6 并发、超时与凭据刷新

- **同一账号串行**：针对同一个 `unionid` 的操作会排队执行（`/api/code` 的 `type=2` 快速取码除外）。并发调用同一账号时，后到的请求会等待前一个完成，再加上自身的执行时间。不同账号之间互不影响。
- **服务端超时**：每个接口都有超时上限（各接口小节中给出）。超时时，有的接口返回 `504`，有的返回 `200` 并在失败字段中说明，以各接口说明为准。
- **CK 自动刷新**：当应用宝返回凭据过期时，服务会用 `refresh_token` 自动刷新一次并重试本次调用，调用方无需关心。刷新也失败时（例如 `refresh_token` 已失效），只能重新扫码。希望在凭据失效前主动换一套新 CK，用 `/api/renewck`。
- **协议状态回写**：标准取码、手机号、operateWXData、Transfer、公众号授权等走微信协议的接口，执行后会把更新的协议登录态写回账号记录，因此 `GET /api/users` 中账号的 `duration` 和部分字段会随之变化。

## 2. 接口一览

按典型使用顺序排列：先扫码得到账号，再用账号的 `unionid` 调用其他接口。

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

## 3. 扫码登录

扫码登录是账号的唯一来源。流程：

1. `POST /api/scan` 创建会话，得到 `qr_url`（二维码图片地址）和 `scan_id`。
2. 把二维码展示给用户，用户用微信扫码并在手机上确认。
3. 服务在后台每 2 秒轮询一次微信扫码状态，确认后自动换取应用宝 CK 并保存账号；调用方只需按 `scan_id` 查询状态。
4. 当 `status=completed` 时，`account_unionid` 就是新账号（或被更新的已有账号）的 `unionid`。

会话自创建起 2 分钟内有效；后台轮询最多持续 2 分 45 秒。在 Swagger UI 中执行 `POST /api/scan` 会自动弹出二维码并轮询，结束后在弹窗中显示最终结果。

### POST /api/scan 创建扫码会话

无请求体。

```bash
curl -X POST -H 'Authorization: Bearer <token>' http://127.0.0.1:8080/api/scan
```

成功返回 `200` 和 [ScanSession](#scansession-对象)，此时 `status=waiting`：

```json
{
  "id": 1,
  "status": "waiting",
  "guid": "f4a9…",
  "state": "f4a9…",
  "uuid": "0b1Xk…",
  "qr_url": "https://open.weixin.qq.com/connect/qrcode/0b1Xk…",
  "scan_expires_in": "2M",
  "last_errcode": "",
  "wx_code": "",
  "openid": "",
  "unionid": "",
  "ck_expires_at": "",
  "error": "",
  "duration": "1S"
}
```

失败：

| 状态码 | 条件 |
| --- | --- |
| `502` | 向微信申请二维码失败，或写入本地数据库失败 |

### GET /api/scan 查询扫码会话

| 参数 | 位置 | 必填 | 说明 |
| --- | --- | --- | --- |
| `scan_id` | query | 是 | `POST /api/scan` 返回的 `id`，正整数 |

```bash
curl -H 'Authorization: Bearer <token>' 'http://127.0.0.1:8080/api/scan?scan_id=1'
```

成功返回 `200` 和 [ScanSession](#scansession-对象)。会话结束后仍可查询，返回最终状态。

失败：

| 状态码 | 条件 |
| --- | --- |
| `400` | `scan_id` 缺失，或不是正整数 |
| `404` | 会话不存在 |

### ScanSession 对象

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | integer | 扫码会话 ID，即 `scan_id` |
| `status` | string | 会话状态，取值见下表 |
| `guid` | string | 本次登录在应用宝侧的会话 GUID |
| `state` | string | 本次登录使用的 OAuth `state` |
| `uuid` | string | 微信二维码 UUID |
| `qr_url` | string | 二维码图片地址（PNG），可直接用 `<img>` 展示 |
| `scan_expires_in` | string | 距离会话过期的剩余时间，见 [1.4](#14-时长字段)；会话结束后为 `0S` |
| `last_errcode` | string | 微信扫码接口最近一次返回的状态码原文：`408` 未扫码、`404` 已扫码待确认、`405` 已确认、`403` 用户取消、`402` 二维码过期 |
| `wx_code` | string | 用户确认后微信返回的授权 code；服务已用它换取 CK，仅作记录 |
| `openid` | string | 登录成功后的应用宝 openid，完成前为空 |
| `unionid` | string | 登录成功后的微信 unionid，完成前为空 |
| `account_unionid` | string | 本次登录保存或更新的账号 `unionid`；未关联账号（未完成、或账号已被删除）时省略 |
| `ck_expires_at` | string | 关联账号的 CK 到期时间，见 [User 对象](#user-对象)；未关联账号时为空 |
| `error` | string | `status=failed` 时的失败原因，其余为空 |
| `duration` | string | 会话从创建到最近一次更新的时长 |

`status` 取值：

| 值 | 含义 | 是否终态 |
| --- | --- | --- |
| `waiting` | 等待扫码 | 否 |
| `scanned` | 已扫码，等待用户在手机上确认 | 否 |
| `authorized` | 用户已确认，正在换取 CK 并保存账号。这一步通常在同一次轮询内完成，一般观察不到 | 否 |
| `completed` | 账号已保存或更新，`account_unionid` 可用 | 是 |
| `canceled` | 用户在手机上取消了登录 | 是 |
| `expired` | 超过 2 分钟未完成 | 是 |
| `failed` | 轮询、换取 CK 或保存账号失败，原因在 `error` | 是 |

## 4. 账号管理

### GET /api/users 获取账号列表

```bash
curl -H 'Authorization: Bearer <token>' http://127.0.0.1:8080/api/users
```

成功返回 `200` 和 [User](#user-对象) 数组。

- 按首次入库顺序返回：刷新凭据或重复扫码同一账号不会改变顺序，新账号追加在末尾。
- 没有分页和筛选，调用方按 `unionid` 自行查找。
- 响应包含 `access_token`、`refresh_token` 和协议密钥等敏感信息，请勿暴露给不可信的调用方。

失败：

| 状态码 | 条件 |
| --- | --- |
| `500` | 读取数据库失败 |

### POST /api/users 删除账号

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `unionid` | string | 是 | 要删除的账号 |

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx"}' \
  http://127.0.0.1:8080/api/users
```

成功返回 `200`：

```json
{
  "ok": true,
  "unionid": "o_xxx",
  "deleted": true,
  "detached_scan_sessions": 3
}
```

| 字段 | 说明 |
| --- | --- |
| `detached_scan_sessions` | 与该账号关联的扫码历史条数。扫码历史会保留，只是解除与账号的关联 |

失败：

| 状态码 | 条件 |
| --- | --- |
| `400` | 请求体不合法或 `unionid` 缺失 |
| `404` | 账号不存在 |
| `500` | 删除时数据库操作失败 |

### POST /api/renewck 换发应用宝 CK

在不重新扫码的情况下，为已有账号换发一套新的应用宝 CK（新的 `access_token`、`refresh_token`、`guid` 和到期时间）。服务使用账号当前保存的 CK 和微信协议登录态，自动完成应用宝授权、确认、获取授权 code 和兑换新 CK 的全过程；调用方只需提供 `unionid`。换新使用的应用宝 AppID 固定为 `wxd44977328b36e647`，授权 scope 固定为 `snsapi_login,snsapi_runtime_pcsdk`。

执行步骤和失败点：

1. 读取账号，要求账号具备完整的 CK、`guid`、设备标识和协议登录态，否则 `OLD_SESSION_INVALID`。
2. 向微信申请新的授权会话，并用旧登录态完成授权和确认（`authorize` / `confirm` 阶段）。旧登录态失效时 `OLD_SESSION_INVALID`，微信拒绝时 `QRCONNECT_REJECTED`。
3. 轮询授权 code，最多 20 秒（`poll` 阶段）。
4. 用 code 兑换新 CK（`exchange` 阶段）。兑换出的 `openid` 必须与原账号一致，否则 `ACCOUNT_MISMATCH`，此时不会保存。
5. 保存新 CK 并回读核对（`save` 阶段）。保存成功后 `ck_updated=true`。
6. 用新 CK 获取一次微信用户资料，核对 `openid` 和 `unionid`（`userinfo` 阶段）。失败返回 `CK_VALIDATION_FAILED`，但**新 CK 已保存且会保留**，不会回退到旧 CK。

整个流程的时限为 75 秒。一旦进入确认阶段，即使调用方断开连接，服务也会在剩余时限内继续完成兑换和保存。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `unionid` | string | 是 | 要换新的账号。请求体不能包含其他字段 |

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx"}' \
  http://127.0.0.1:8080/api/renewck
```

成功返回 `200`，返回的凭据即数据库中保存的新凭据：

```json
{
  "ok": true,
  "ck_updated": true,
  "unionid": "o_xxx",
  "openid": "o_xxx",
  "appid": "wxd44977328b36e647",
  "guid": "new-guid",
  "login_type": "WX",
  "access_token": "NEW_ACCESS_TOKEN",
  "refresh_token": "NEW_REFRESH_TOKEN",
  "ck_expires_at": "Wed, 02 Dec 2026 00:00:00 GMT",
  "scope": "snsapi_login,snsapi_runtime_pcsdk",
  "userinfo_ok": true,
  "duration": "8S"
}
```

| 字段 | 说明 |
| --- | --- |
| `ok` | 整个流程成功，含用户资料校验 |
| `ck_updated` | 新 CK 是否已写入数据库。失败响应中也会返回，用于判断凭据是否已经被替换 |
| `openid`、`guid`、`login_type`、`access_token`、`refresh_token`、`ck_expires_at` | 新凭据，含义同 [User 对象](#user-对象)；`ck_expires_at` 在上游未提供到期时间时省略 |
| `appid` | 固定为 `wxd44977328b36e647` |
| `scope` | 固定为 `snsapi_login,snsapi_runtime_pcsdk` |
| `userinfo_ok` | 新 CK 的用户资料校验是否通过 |
| `duration` | 本次请求耗时 |

失败时返回同样结构的对象，`ok=false`，凭据字段省略，并带 `error`：

```json
{
  "ok": false,
  "ck_updated": true,
  "unionid": "o_xxx",
  "appid": "wxd44977328b36e647",
  "userinfo_ok": false,
  "error": {
    "code": "CK_VALIDATION_FAILED",
    "stage": "userinfo",
    "message": "新 CK 已保存，用户信息校验失败"
  },
  "duration": "8S"
}
```

`error` 字段：

| 字段 | 说明 |
| --- | --- |
| `code` | 错误码，见下表 |
| `stage` | 失败阶段：`request`、`account`、`scan`、`authorize`、`confirm`、`poll`、`exchange`、`save`、`userinfo`、`renew` |
| `message` | 错误描述 |
| `wechat_ret` | 微信返回的业务错误码，仅在上游给出时存在 |

错误码与 HTTP 状态码：

| 状态码 | `error.code` | 条件 | `ck_updated` |
| --- | --- | --- | --- |
| `400` | `INVALID_REQUEST` | 请求体不是只含 `unionid` 的 JSON 对象，或 `unionid` 为空 | `false` |
| `404` | `ACCOUNT_NOT_FOUND` | 账号不存在 | `false` |
| `409` | `OLD_SESSION_INVALID` | 账号缺少必要的凭据或设备信息，或旧登录态已失效，需要重新扫码 | `false` |
| `409` | `ACCOUNT_MISMATCH` | 兑换出的 `openid` 与原账号不一致，新凭据未保存 | `false` |
| `422` | `QRCONNECT_REJECTED` | 微信拒绝授权，或授权会话被取消、过期；`wechat_ret` 为微信错误码 | `false` |
| `500` | `CK_SAVE_FAILED` | 读取账号、保存授权登录态、保存新 CK 或回读核对失败。保存后的回读失败时 `ck_updated` 仍为 `true` | 视阶段而定 |
| `502` | `CK_RENEW_UPSTREAM_ERROR` | 申请授权会话、授权、确认、轮询或兑换阶段上游异常，或返回的凭据不完整 | `false` |
| `502` | `CK_VALIDATION_FAILED` | 新 CK 已保存，但用户资料请求失败、返回业务错误或身份不匹配 | `true` |
| `504` | `CK_RENEW_TIMEOUT` | 超过 75 秒，或在确认前被取消。若超时发生在保存之后的用户资料校验阶段，则返回 `502` `CK_VALIDATION_FAILED` | 视阶段而定 |

注意鉴权失败的 `401` 使用通用错误形态 `{"error": "..."}`，不含 `ck_updated`。

### User 对象

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `unionid` | string | 微信 unionid，账号唯一标识 |
| `openid` | string | 该账号在应用宝微信登录下的 openid |
| `guid` | string | 应用宝登录会话 GUID，扫码或换新 CK 时生成 |
| `login_type` | string | 固定为 `WX` |
| `access_token` | string | 应用宝 CK 的 access token |
| `refresh_token` | string | 应用宝 CK 的 refresh token，用于自动刷新 |
| `ck_expires_at` | string | CK 到期时间，取自应用宝 OAuth 响应 `Set-Cookie` 的 `Expires`（RFC 1123 格式，如 `Mon, 27 Jul 2026 10:14:30 GMT`）；上游未提供时为空 |
| `wx_code` | string | 最近一次登录拿到的微信授权 code，已被使用，仅作记录 |
| `state` | string | 最近一次登录使用的 OAuth `state` |
| `device_id_b64` | string | 服务为该账号生成的微信协议设备 ID（base64）。首次入库时生成，之后固定不变 |
| `app_device_id` | string | 设备 ID 的另一种表示（hex 前 16 位），与 `device_id_b64` 对应 |
| `username` | string | 微信协议层用户名，形如 `<openid>@im.ilinkapp_…` |
| `uin` | string | 微信协议层 uin。首次扫码后为空，成功执行过标准取码等协议操作后填充 |
| `autoauth_key_b64` | string | 微信协议层自动登录密钥（base64），填充时机同 `uin` |
| `autoauth_enc_key_b64` | string | 微信协议层会话加密密钥（base64），填充时机同 `uin` |
| `duration` | string | 从首次入库到最近一次更新的时长 |

## 5. 微信能力

本章接口都以某个账号的身份执行微信侧操作，请求中都需要 `unionid`。

### POST /api/getuserinfo 获取微信用户资料

调用微信 `sns/userinfo` 接口，返回昵称、头像等 OAuth 用户资料。注意这是微信开放平台的资料字段（`nickname`、`headimgurl`），不是小程序 `wx.getUserInfo` 的 `nickName` / `avatarUrl` 形态。超时 20 秒。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `unionid` | string | 是 | 账号 |
| `lang` | string | 否 | 资料语言：`zh_CN`（默认）、`zh_TW` 或 `en` |

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx","lang":"zh_CN"}' \
  http://127.0.0.1:8080/api/getuserinfo
```

成功返回 `200`：

```json
{
  "ok": true,
  "unionid": "o_xxx",
  "openid": "o_xxx",
  "nickname": "昵称",
  "headimgurl": "https://thirdwx.qlogo.cn/…",
  "sex": 0,
  "country": "",
  "province": "",
  "city": "",
  "privilege": [],
  "duration": "1S"
}
```

| 字段 | 说明 |
| --- | --- |
| `ok` | 是否成功拿到资料。微信返回业务错误时为 `false`，并附带 `errcode` / `errmsg` |
| `unionid`、`openid` | 微信返回的标识；微信未返回时使用账号记录中的值 |
| `nickname`、`headimgurl`、`sex`、`country`、`province`、`city`、`privilege` | 微信 `sns/userinfo` 的原始字段。`sex`：`0` 未知、`1` 男、`2` 女 |
| `errcode`、`errmsg` | 微信业务错误码和描述，成功时省略 |
| `duration` | 本次请求耗时 |

失败：

| 状态码 | 条件 |
| --- | --- |
| `200` + `ok=false` | 微信返回业务错误（`errcode` 非 0） |
| `400` | `unionid` 缺失；`lang` 不在允许范围；账号缺少 `openid` 或 `access_token` |
| `404` | 账号不存在 |
| `502` | 请求微信失败（网络错误或非 2xx）；CK 过期且自动刷新失败 |
| `504` | 超过 20 秒，含等待同账号前一个操作的时间 |

### POST /api/code 获取小程序 code

获取账号在指定小程序下的登录 code（等价于小程序内 `wx.login` 得到的 code，可拿去换 `session_key` / `openid`）。一次请求只取一个 `appid`，多个小程序请依次调用。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `unionid` | string | 是 | 账号 |
| `appid` | string | 是 | 目标小程序 AppID |
| `type` | integer | 是 | 取码方式：`1` 标准取码，`2` 快速取码，见下 |

两种取码方式：

| `type` | 名称 | 方式 | 超时 | 特点 |
| --- | --- | --- | --- | --- |
| `1` | 标准取码 | 走微信长连接协议（ManualAuth + JSLogin），使用账号保存的设备和协议登录态 | 75 秒 | 与微信客户端行为一致，成功率高；会更新账号的协议登录态；同一账号串行执行 |
| `2` | 快速取码 | 调用应用宝 PC 端 HTTP 接口，只依赖 `unionid` 与 `appid` | 15 秒 | 快，不占用账号锁，不改动本地登录态；依赖应用宝侧对该账号的绑定状态 |

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx","appid":"wx7c45a544886d9e69","type":1}' \
  http://127.0.0.1:8080/api/code
```

成功返回 `200`：

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

| 字段 | 说明 |
| --- | --- |
| `status` | `succeeded` 或 `failed` |
| `code` | 小程序登录 code，失败时为空 |
| `error` | 失败原因，成功时为空。快速取码常见上游错误：`-109` 表示 `appid` 无效，`-105` 表示该账号在应用宝侧的会话不可用 |
| `duration` | 本次取码耗时 |

失败：

| 状态码 | 条件 |
| --- | --- |
| `200` + `status=failed` | 协议或上游调用失败，包括超时；原因在 `error` |
| `400` | `unionid`、`appid` 或 `type` 缺失；`type` 不是 `1` 或 `2` |
| `404` | 账号不存在 |
| `504` | 标准取码等待同账号前一个操作超过 75 秒 |

### POST /api/getphone 获取手机号

以账号身份走微信协议获取其在指定小程序下绑定的手机号，相当于小程序内 `getPhoneNumber` 按钮的授权回调。超时 75 秒。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `unionid` | string | 是 | 账号 |
| `appid` | string | 是 | 目标小程序 AppID |

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx","appid":"wxde7e5cd3f013ff7d"}' \
  http://127.0.0.1:8080/api/getphone
```

成功返回 `200`：

```json
{
  "ok": true,
  "mobile": "13800000000",
  "show_mobile": "138****0000",
  "encryptedData": "…",
  "iv": "…",
  "code": "…",
  "data": "{\"code\":\"…\"}",
  "duration": "2S"
}
```

| 字段 | 说明 |
| --- | --- |
| `ok` | 是否拿到明文手机号（`mobile` 非空） |
| `mobile` | 明文手机号 |
| `show_mobile` | 脱敏手机号 |
| `encryptedData`、`iv` | 微信回调中的加密载荷，可按小程序开放数据解密流程解密 |
| `code` | 手机号 code，可用微信服务端接口换取手机号；优先取回调中的 `code`，否则从 `data` 中提取 |
| `data` | 微信回调 `wx_phone.data` 的原始 JSON 文本，为空时省略 |
| `cloud_id`、`request_id` | 微信回调中的云调用 ID 和请求 ID，为空时省略 |
| `error` | 协议或上游错误原因，成功时省略 |
| `duration` | 本次请求耗时 |

失败：

| 状态码 | 条件 |
| --- | --- |
| `200` + `ok=false` | 协议调用失败、超时，或响应中没有手机号；原因在 `error` |
| `400` | `unionid` 或 `appid` 缺失；账号缺少 `openid` |
| `404` | 账号不存在 |
| `504` | 等待同账号前一个操作超过 75 秒 |

### POST /api/oauthauthorize 发起公众号网页授权

以账号身份模拟用户打开公众号网页授权链接（`https://open.weixin.qq.com/connect/oauth2/authorize?...`）。微信可能直接放行（静默授权或近期已授权），此时直接返回 code；也可能要求用户确认，此时返回待确认信息，需要再调用 `/api/oauthconfirm`。超时 75 秒。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `unionid` | string | 是 | 账号 |
| `appid` | string | 是 | 公众号 AppID，格式 `wx` + 16 位十六进制 |
| `redirect_uri` | string | 是 | 授权回调地址，必须是绝对 `http` / `https` URL，不能带用户信息和 fragment |
| `scope` | string | 是 | `snsapi_base` 或 `snsapi_userinfo` |
| `state` | string | 否 | OAuth `state`，只允许 `A-Z a-z 0-9 . _ ~ -`，最长 128 字符；省略时由服务随机生成 |
| `biz_username` | string | 否 | 公众号原始 ID（`gh_` 开头），透传给微信 |
| `scene` | integer | 否 | 微信授权场景值，默认 `0`，不能为负 |
| `referrer_url` | string | 否 | 来源页面地址，必须是绝对 `http` / `https` URL |
| `sub_scene` | integer | 否 | 微信授权子场景值，不能为负 |
| `auto_oauth` | boolean | 否 | 是否按微信"自动授权"方式请求 |

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx","appid":"wx1234567890abcdef","redirect_uri":"https://example.com/oauth/callback","scope":"snsapi_userinfo"}' \
  http://127.0.0.1:8080/api/oauthauthorize
```

成功返回 `200`。`status=completed` 表示已直接拿到 code：

```json
{
  "status": "completed",
  "unionid": "o_xxx",
  "appid": "wx1234567890abcdef",
  "scope": "snsapi_userinfo",
  "state": "STATE",
  "authorization_url": "",
  "code": "011xxx",
  "is_recent_has_auth": true,
  "is_silent_auth": false,
  "scope_list": [],
  "avatar_list": [],
  "duration": "2S"
}
```

`status=confirmation_required` 表示需要确认，把 `authorization_url` 原样传给 `/api/oauthconfirm`：

```json
{
  "status": "confirmation_required",
  "unionid": "o_xxx",
  "appid": "wx1234567890abcdef",
  "scope": "snsapi_userinfo",
  "state": "STATE",
  "authorization_url": "https://open.weixin.qq.com/connect/oauth2/authorize?appid=…&redirect_uri=…&response_type=code&scope=snsapi_userinfo&state=STATE#wechat_redirect",
  "code": "",
  "is_recent_has_auth": false,
  "is_silent_auth": false,
  "scope_list": [
    { "scope": "snsapi_userinfo", "desc": "获取你的昵称、头像、地区及性别", "auth_state": 0, "ext_desc": "", "auth_sub_desc": "" }
  ],
  "avatar_list": [
    { "id": "0", "nickname": "昵称", "avatarurl": "https://thirdwx.qlogo.cn/…" }
  ],
  "duration": "2S"
}
```

| 字段 | 说明 |
| --- | --- |
| `status` | `completed` 已拿到 code；`confirmation_required` 需要调用 `/api/oauthconfirm` |
| `state` | 实际使用的 `state`（请求省略时为服务生成的值） |
| `authorization_url` | 需要确认时的授权地址，用于 `/api/oauthconfirm`；已完成时为空 |
| `code` | 公众号网页授权 code，仅 `completed` 时非空 |
| `is_recent_has_auth` | 微信标记：该用户近期已对此公众号授权 |
| `is_silent_auth` | 微信标记：本次为静默授权 |
| `scope_list` | 微信返回的待授权权限说明列表 |
| `avatar_list` | 微信返回的可选头像/身份列表，`id` 可作为 `/api/oauthconfirm` 的 `avatar_id` |
| `duration` | 本次请求耗时 |

### POST /api/oauthconfirm 确认公众号网页授权

对 `/api/oauthauthorize` 返回的 `authorization_url` 执行"同意授权"，获取 code。超时 75 秒。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `unionid` | string | 是 | 账号，必须与发起授权时相同 |
| `appid` | string | 是 | 公众号 AppID，必须与 `authorization_url` 中的一致 |
| `authorization_url` | string | 是 | `/api/oauthauthorize` 返回的授权地址。必须是 `https://open.weixin.qq.com/connect/oauth2/authorize` 且带 `#wechat_redirect`，`response_type=code`，长度不超过 8192，且不能含 `code` 参数 |
| `avatar_id` | string | 否 | `avatar_list[].id`，非负 32 位整数文本；省略时为 `0` |

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx","appid":"wx1234567890abcdef","authorization_url":"https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx1234567890abcdef&redirect_uri=https%3A%2F%2Fexample.com%2Foauth%2Fcallback&response_type=code&scope=snsapi_userinfo&state=STATE#wechat_redirect","avatar_id":"0"}' \
  http://127.0.0.1:8080/api/oauthconfirm
```

成功返回 `200`：

```json
{
  "status": "completed",
  "unionid": "o_xxx",
  "appid": "wx1234567890abcdef",
  "code": "011xxx",
  "state": "STATE",
  "redirect_uri": "https://example.com/oauth/callback",
  "duration": "1S"
}
```

公众号授权两个接口共用的失败返回（结构化错误，见 [1.5](#15-错误返回)）：

| 状态码 | `error.code` | 条件 |
| --- | --- | --- |
| `400` | `INVALID_REQUEST` | 请求体不合法，或任一字段校验不通过，`message` 说明具体字段 |
| `404` | `ACCOUNT_NOT_FOUND` | 账号不存在 |
| `422` | `OAUTH_BUSINESS_REJECTED` | 微信拒绝授权，`wechat_ret` / `wechat_message` 为微信返回的错误码和描述 |
| `502` | `OAUTH_UPSTREAM_ERROR` | 协议调用失败、响应无法解析、`state` 不匹配、确认后未返回 code、CK 刷新失败等 |
| `504` | `OAUTH_TIMEOUT` | 超过 75 秒 |

## 6. 协议调试

本章接口直接暴露微信长连接协议的请求构造和响应解码，主要用于调试和扩展，调用方需要了解对应协议。两者都会返回 `request` / `response` 两组追踪信息：

| 字段 | 说明 |
| --- | --- |
| `request.cgi` | 实际发送的 CGI 路径 |
| `request.wrapper_len`、`request.out_body_len` | 外层信封和加密后请求体的字节数 |
| `request.pack_round_trip_ok` | 服务端自检：把刚加密的请求体解密、解压后能否还原出原始信封，`false` 说明本地会话密钥有问题 |
| `response.source` | 响应来源，如 `longlinkPack` |
| `response.task_id`、`response.tag4`、`response.tag23`、`response.body_len` | 长连接响应帧的元信息和原始体长度 |
| `response.decode_mode` | 解密方式：`raw89-sessionField2`、`raw89-sessionField3`、`raw89-packrequest` 或 `direct-proto`（响应未加密） |
| `response.plain_len` | 解密后明文长度 |

### POST /api/operatewxdata 调用 operateWXData

以账号身份调用小程序 `operateWXData`（CGI `/cgi-bin/mmbiz-bin/js-operatewxdata`），这是小程序云开发、云函数、云网关等能力的底层入口。超时 75 秒。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `unionid` | string | 是 | 账号 |
| `appid` | string | 是 | 目标小程序 AppID |
| `type` | integer | 是 | 请求模式：`1` 原样、`2` 云函数、`3` 云网关三元组，见下 |
| `operate_code` | integer | 否 | `operateWXData` 的 `operate_code`，默认 `1`，不能为负 |
| `function_name` | string | `type=2` 时必填 | 云函数名 |
| `data` | object / array / string | 是 | 含义随 `type` 不同，见下；`type=3` 时可传 `{}` |

三种模式：

| `type` | 模式 | `data` 的含义 |
| --- | --- | --- |
| `1` | 原样模式 | 完整的 `operateWXData.data`，由调用方自行构造。对象或数组会压缩成 JSON 字符串发送，字符串原样发送 |
| `2` | 云函数模式 | 云函数的业务入参。服务会自动包装成 `qbase_commapi` / `tcbapi_slowcallfunction_v2` 调用，并生成 `call_id`、`cli_req_id` 等字段 |
| `3` | 云网关三元组模式 | 可选的请求参数覆盖（见下表）。服务会调用 `tcbapi_get_service_info`，并从响应中提取云网关的 `token` / `key` / `rid` |

`type=3` 时 `data` 允许的字段（都可省略，不接受其他字段）：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `system` | `Android 12` | 上报的系统版本 |
| `wx_app_version` | `8.0.74` | 上报的微信版本 |
| `scene` | `3` | 场景值，不能为负 |
| `sdk_version` | `wx-miniprogram-sdk/3.16.2 …` | 上报的 SDK 版本 |
| `env` | `1` | 环境标识，1–255 |
| `session_id` | 当前毫秒时间戳 | 会话 ID |
| `cli_req_id` | 自动生成 | 客户端请求 ID |
| `rid` | 按协议算法自动生成 | 追踪 ID，写入 `qbase_options.rid` |
| `rv` | `2` | `qbase_options.rv` |
| `kx` | 自动生成 | 客户端 X25519 公钥（hex） |
| `client_private_key` | 自动生成 | 客户端 X25519 私钥（hex）。省略时服务生成一对密钥；只传 `kx` 不传私钥时无法派生 `key` |

请求示例，云函数模式：

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx","appid":"wx887bf6ad752ca2f3","type":2,"function_name":"rsa","data":{"score":"350|1782791141326"}}' \
  http://127.0.0.1:8080/api/operatewxdata
```

原样模式：

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx","appid":"wx887bf6ad752ca2f3","type":1,"data":{"api_name":"qbase_commapi","data":{},"operate_directly":false}}' \
  http://127.0.0.1:8080/api/operatewxdata
```

云网关三元组模式：

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx","appid":"wxde7e5cd3f013ff7d","type":3,"data":{}}' \
  http://127.0.0.1:8080/api/operatewxdata
```

成功返回 `200`（以 `type=3` 为例，`gateway_service_info` 只在该模式返回）：

```json
{
  "ok": true,
  "appid": "wxde7e5cd3f013ff7d",
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

| 字段 | 说明 |
| --- | --- |
| `ok` | 协议调用成功并解出了响应。业务是否成功要看 `decoded` 中的 `err_no` 等字段 |
| `appid`、`operate_code` | 回显请求参数 |
| `request`、`response` | 协议追踪信息，见本章开头 |
| `decoded` | 从响应明文中找到的 JSON 对象（含 `err_no`、`data` 或 `baseresponse` 之一）；找不到时省略 |
| `decoded_raw` | `decoded` 对应的原始 JSON 文本；找不到时省略 |
| `gateway_service_info` | 仅 `type=3`：三元组提取结果，见下表 |
| `duration` | 本次请求耗时 |

`gateway_service_info` 字段：

| 字段 | 说明 |
| --- | --- |
| `ok` | 是否成功提取出 `token` 和 `key` |
| `token` | 云网关 token |
| `key` | 云网关 AES key（base64）。上游直接返回时原样给出，否则用客户端私钥和 `server_kx` 做 X25519 + HKDF 派生 |
| `rid` | 上游返回的业务 rid；上游未返回时回退为请求的 `qbase_rid` |
| `qbase_rid` | 本次请求 `qbase_options.rid` 的完整值 |
| `kx` | 上游返回的服务端 X25519 公钥（hex），为空时省略 |
| `client_kx` | 本次请求使用的客户端 X25519 公钥（hex） |
| `server_kx` | 实际用于派生 `key` 的服务端公钥；`key` 由上游直接返回时省略 |
| `iat`、`exp` | 上游返回的签发/过期时间，原样透传，为空时省略 |
| `source` | 固定为 `tcbapi_get_service_info` |
| `error` | `ok=false` 时的原因，例如响应中缺少 token 或 key。此时 `decoded` / `decoded_raw` 仍会返回，便于排查 |

失败：

| 状态码 | 条件 |
| --- | --- |
| `400` | 参数缺失或不合法（含 `type=3` 的 `data` 字段校验） |
| `404` | 账号不存在 |
| `502` | 协议调用失败，或响应无法解密 / 解码 |
| `504` | 超过 75 秒，含等待同账号前一个操作的时间 |

### POST /api/transfer 通用 Transfer 请求

以账号身份向任意 CGI 发送 Transfer 协议请求，并按指定方式解码响应。`/api/code`（标准取码）和 `/api/operatewxdata` 的底层都是这类请求，本接口把信封和传输参数全部开放出来，用于调试新协议。超时 75 秒。

请求字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `unionid` | string | 是 | 账号 |
| `appid` | string | 是 | 目标 AppID，写入外层信封字段 6 |
| `cgi` | string | 是 | CGI 路径，必须以 `/` 开头，不能带 scheme、host、用户信息或 fragment，最长 2048 |
| `route` | integer | 否 | 外层信封 route，默认 `1029`，必须大于 0 |
| `inner_mode` | string | 否 | inner body 的构造方式：`standard`（默认）、`protobuf` 或 `raw`，见下 |
| `data_format` | string | 否 | `standard` 模式下 `data` 的格式：`none`（默认）、`json`、`text` 或 `base64` |
| `data` | 任意 | 否 | `standard` 模式下的字段 3 内容：`json` 时为任意 JSON（压缩后作为字符串发送）；`text` / `base64` 时必须是 JSON 字符串；`none` 时省略或为 `null` |
| `inner_fields` | array | `protobuf` 模式必填 | 逐字段描述 inner body，最多 256 个，见下 |
| `inner_base64` | string | `raw` 模式必填 | 完整 inner body 的标准 base64 |
| `outer` | object | 否 | 外层信封覆盖，见下 |
| `transport` | object | 否 | 长连接传输层覆盖，见下 |
| `response_mode` | string | 否 | 响应解码方式：`auto`（默认，依次尝试 JSON、protobuf、raw）、`json`、`protobuf` 或 `raw` |

三种 `inner_mode`：

| 模式 | 构造方式 | 允许的字段 |
| --- | --- | --- |
| `standard` | 字段 1 = session_base，字段 2 = target_appid，字段 3 = `data`（`data_format=none` 时不写字段 3） | `data_format`、`data`；不接受 `inner_fields`、`inner_base64` |
| `protobuf` | 按 `inner_fields` 逐字段编码 | `inner_fields`；不接受 `data_format`、`data`、`inner_base64` |
| `raw` | 直接使用 `inner_base64` 解码后的字节 | `inner_base64`；不接受 `data_format`、`data`、`inner_fields` |

`inner_fields[]` 的结构：

| 字段 | 说明 |
| --- | --- |
| `number` | protobuf 字段号，1–536870911，且不能落在保留段 19000–19999 |
| `type` | 字段类型，见下表 |
| `value` | `string` 类型的文本，或 `bytes` 类型的标准 base64 |
| `uint` | `varint`、`fixed32`、`fixed64` 类型的无符号整数值；`fixed32` 不能超过 32 位 |

| `type` | 说明 | 需要的值 |
| --- | --- | --- |
| `session_base` | 模板：服务端填入会话基础信息 | 无，不能传 `value` / `uint` |
| `target_appid` | 模板：服务端填入请求的 `appid` | 同上 |
| `host_appid` | 模板：服务端填入宿主 AppID（`outer.host_appid` 或默认值） | 同上 |
| `ilink_appid` | 模板：服务端填入内置的 ilink AppID（`ilinkapp_060000b7b93f6c`） | 同上 |
| `string` | UTF-8 文本 | `value` |
| `bytes` | 二进制 | `value`（标准 base64） |
| `varint` / `fixed32` / `fixed64` | 整数 | `uint` |

`outer` 的字段（都可省略，省略时使用默认值）：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `host_appid` | `wxd44977328b36e647` | 宿主 AppID，最长 128 字符 |
| `field4` | `5` | 外层信封字段 4 |
| `field8` | `1610627409`（`0x60003951`） | 外层信封字段 8 |
| `plugin` | `WindowsxWebPlugin` | 外层信封插件名，最长 256 字符 |
| `field10` | `573651281`（`0x22313951`） | 外层信封字段 10 |

`transport` 的字段（都可省略）：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `sequence` | `4` | 长连接序号，必须大于 0 |
| `task_id` | `2881` | 任务 ID，必须大于 0 |
| `task_type` | `2` | 任务类型 |
| `identity_mode` | `account` | 长连接包头的身份：`account` 携带账号 uin；`zero` 使用 uin 为 0 的匿名包头（ManualAuth 等登录前阶段使用） |

请求示例（`standard` 模式 + JSON data）：

```bash
curl -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"unionid":"o_xxx","appid":"wx887bf6ad752ca2f3","cgi":"/cgi-bin/mmbiz-bin/js-operatewxdata","data_format":"json","data":{"api_name":"qbase_commapi","data":{}}}' \
  http://127.0.0.1:8080/api/transfer
```

成功返回 `200`：

```json
{
  "ok": true,
  "unionid": "o_xxx",
  "appid": "wx887bf6ad752ca2f3",
  "cgi": "/cgi-bin/mmbiz-bin/js-operatewxdata",
  "route": 1029,
  "data_format": "json",
  "inner_mode": "standard",
  "response_mode": "auto",
  "decoded": {},
  "decoded_format": "json",
  "decoded_raw": "{}",
  "plain_base64": "…",
  "request": {
    "cgi": "/cgi-bin/mmbiz-bin/js-operatewxdata",
    "route": 1029,
    "sequence": 4,
    "task_id": 2881,
    "task_type": 2,
    "identity_mode": "account",
    "inner_mode": "standard",
    "inner_body_len": 128,
    "host_appid": "wxd44977328b36e647",
    "outer_field4": 5,
    "outer_field8": 1610627409,
    "plugin": "WindowsxWebPlugin",
    "outer_field10": 573651281,
    "wrapper_len": 762,
    "out_body_len": 623,
    "pack_round_trip_ok": true
  },
  "response": {
    "source": "longlinkPack",
    "sequence": 4,
    "task_id": 2881,
    "task_type": 2,
    "tag4": 0,
    "tag23": 0,
    "body_len": 663,
    "decode_mode": "raw89-sessionField2",
    "plain_len": 684
  },
  "duration": "1S"
}
```

| 字段 | 说明 |
| --- | --- |
| `ok` | 协议调用成功并解出了响应明文。使用 protobuf 时业务是否成功仍需检查解出的 BaseResponse 返回码 |
| `unionid`、`appid`、`cgi`、`route`、`inner_mode`、`response_mode` | 回显实际使用的参数 |
| `data_format` | `standard` 模式下实际使用的格式；其他模式省略 |
| `decoded_format` | 实际的解码结果格式：`json`、`protobuf` 或 `raw` |
| `decoded` | `json`：解析后的 JSON；`protobuf`：结构化字段树，见下；`raw`：`null` |
| `decoded_raw` | `json` 时为原始 JSON 文本，其余为空 |
| `plain_base64` | 解密后的响应明文，标准 base64 |
| `request`、`response` | 协议追踪信息，见本章开头；`request` 额外包含实际使用的 `outer` / `transport` 参数和 `inner_body_len` |
| `duration` | 本次请求耗时 |

`decoded_format=protobuf` 时 `decoded` 的结构：

```json
{
  "format": "protobuf",
  "fields": [
    { "number": 1, "wire": "bytes", "nested": [ { "number": 1, "wire": "varint", "varint": 0 } ] },
    { "number": 2, "wire": "bytes", "text": "..." }
  ],
  "strings": ["..."],
  "code_candidates": ["..."]
}
```

| 字段 | 说明 |
| --- | --- |
| `fields[]` | 逐字段解析结果：`number` 字段号，`wire` 线型；按线型给出 `varint`、`fixed32`、`fixed64`、`text`（可打印文本）、`base64`（二进制）或 `nested`（可继续解析为 protobuf 的子消息） |
| `strings` | 响应中所有可打印字符串 |
| `code_candidates` | 看起来像授权 code 的字符串，便于快速定位 |

失败（通用错误形态）：

| 状态码 | 条件 |
| --- | --- |
| `400` | 参数缺失或校验不通过，`error` 说明具体字段 |
| `404` | 账号不存在 |
| `502` | 协议调用失败，或响应无法解密 / 解码 |
| `504` | 超过 75 秒，含等待同账号前一个操作的时间 |
