package native

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
	"yyb-auth-service/internal/tdi"
	"yyb-auth-service/internal/yyb"
)

const (
	manualAuthCmdID    = 3453
	manualAuthTaskType = 2
	defaultTimeout     = 12 * time.Second
)

type Engine struct {
	client      *yyb.Client
	credentials FreshLoginBufferProvider
	timeout     time.Duration
}

type FreshLoginBufferProvider interface {
	FreshLoginBuffer(
		ctx context.Context,
		unionID string,
	) (model.Account, yyb.FreshLoginBuffer, error)
}

type Result struct {
	Code                string
	RawResultJSON       string
	UpdatedSavedSession session.SavedSession
}

type exchangeTrace struct {
	Endpoint   *LonglinkEndpoint `json:"endpoint,omitempty"`
	Fresh      freshTrace        `json:"fresh"`
	ManualAuth manualAuthTrace   `json:"manualauth"`
	SessionKey sessionKeyTrace   `json:"session_key"`
	JSLogin    jsLoginTrace      `json:"jslogin"`
}

type httpLoginCodeTrace struct {
	Method string `json:"method"`
	AppID  string `json:"appid"`
	Ret    int    `json:"ret"`
	Msg    string `json:"msg,omitempty"`
	Code   string `json:"code,omitempty"`
}

type freshTrace struct {
	FetchedAt      string `json:"fetched_at,omitempty"`
	LoginBufferLen int    `json:"login_buffer_len,omitempty"`
	IlinkAppID     string `json:"ilink_appid,omitempty"`
	MPAppID        string `json:"mp_appid,omitempty"`
}

type manualAuthTrace struct {
	OK             bool   `json:"ok"`
	BaseRet        int    `json:"base_ret,omitempty"`
	ErrMsg         string `json:"err_msg,omitempty"`
	HasAuthSect    bool   `json:"has_auth_sect"`
	HasNetworkSect bool   `json:"has_network_sect"`
	UIN            string `json:"uin,omitempty"`
	SessionBlobLen int    `json:"session_blob_len,omitempty"`
}

type sessionKeyTrace struct {
	Source string `json:"source,omitempty"`
	Length int    `json:"length,omitempty"`
}

type jsLoginTrace struct {
	OK                      bool   `json:"ok"`
	Code                    string `json:"code,omitempty"`
	Ret                     int64  `json:"ret,omitempty"`
	ErrMsg                  string `json:"errmsg,omitempty"`
	DecodeMode              string `json:"decode_mode,omitempty"`
	RequestBodyLen          int    `json:"request_body_len,omitempty"`
	ReplayDecryptsToWrapper bool   `json:"replay_decrypts_to_wrapper"`
	AttemptCount            int    `json:"attempt_count,omitempty"`
	EmptyBodies             int    `json:"empty_bodies,omitempty"`
	DecodeErrors            int    `json:"decode_errors,omitempty"`
	DecodedWithoutCode      int    `json:"decoded_without_code,omitempty"`
}

func NewEngine(
	client *yyb.Client,
	credentials FreshLoginBufferProvider,
) *Engine {
	if client == nil {
		client = yyb.NewClient()
	}
	return &Engine{
		client:      client,
		credentials: credentials,
		timeout:     defaultTimeout,
	}
}

func (e *Engine) ExchangeCodeHTTP(
	ctx context.Context,
	account model.Account,
	appID string,
) (Result, error) {
	saved, err := buildSavedSession(account)
	if err != nil {
		return Result{}, err
	}

	result, err := e.client.GetLoginCodeFast(ctx, account.UnionID, appID)

	trace := httpLoginCodeTrace{
		Method: "fast",
		AppID:  appID,
		Ret:    result.Ret,
		Msg:    result.Msg,
		Code:   result.Code,
	}
	output := Result{
		Code:                result.Code,
		RawResultJSON:       marshalJSON(trace),
		UpdatedSavedSession: saved,
	}
	if err != nil {
		return output, err
	}
	return output, nil
}

func (e *Engine) ExchangeCode(
	ctx context.Context,
	account model.Account,
	appID string,
) (Result, error) {
	account, fresh, err := e.freshLoginBuffer(ctx, account)
	if err != nil {
		return Result{}, err
	}
	saved, err := buildSavedSession(account)
	if err != nil {
		return Result{}, err
	}

	trace := exchangeTrace{}
	finish := func(code string) Result {
		return Result{
			Code:                code,
			RawResultJSON:       marshalTrace(trace),
			UpdatedSavedSession: saved,
		}
	}

	applyFreshLoginBuffer(&saved, fresh)
	trace.Fresh = freshTrace{
		FetchedAt:      fresh.FetchedAt.UTC().Format(time.RFC3339Nano),
		LoginBufferLen: len(fresh.LoginBuffer.Raw),
		IlinkAppID:     fresh.LoginBuffer.IlinkAppID,
		MPAppID:        fresh.LoginBuffer.MPAppID,
	}

	endpoint, err := resolveLonglinkEndpoint(ctx, saved)
	if err != nil {
		return finish(""), err
	}
	trace.Endpoint = &endpoint

	longlink, err := openLonglinkSession(ctx, endpoint.Host, endpoint.Port, e.timeout, true)
	if err != nil {
		return finish(""), err
	}
	defer longlink.Close()

	if strings.TrimSpace(saved.ProtocolDevice.DeviceIDB64) == "" {
		return finish(""), fmt.Errorf("account missing protocol device id")
	}

	tdiCtx := buildTDIContext(saved.ProtocolDevice.DeviceIDB64)
	manualRequest, err := buildManualAuthRequest(tdiCtx, fresh.LoginBuffer.Raw)
	if err != nil {
		return finish(""), err
	}

	manualStage, err := longlink.SendPackedBody(ctx, PackedStage{
		IdentityMode: "zero",
		Body:         manualRequest.HybridRequest,
		Seq:          3,
		TaskID:       manualAuthCmdID,
		TaskType:     manualAuthTaskType,
		Timeout:      e.timeout,
	})
	if err != nil {
		return finish(""), err
	}

	manualResult, err := decodeManualAuthStage(manualStage, manualRequest.RequestState, &saved)
	if err != nil {
		return finish(""), err
	}
	trace.ManualAuth = manualAuthTrace{
		OK:             manualResult.OK,
		BaseRet:        manualResult.BaseRet,
		ErrMsg:         manualResult.ErrMsg,
		HasAuthSect:    manualResult.HasAuthSect,
		HasNetworkSect: manualResult.HasNetworkSect,
		UIN:            manualResult.UIN,
		SessionBlobLen: len(manualResult.SessionBlob),
	}
	if !manualResult.OK {
		return finish(""), fmt.Errorf(
			"manualauth failed baseRet=%d authSect=%t msg=%s",
			manualResult.BaseRet,
			manualResult.HasAuthSect,
			firstNonEmpty(manualResult.ErrMsg, "unknown"),
		)
	}

	sessionKey, keySource, err := resolveSessionKey(saved.ProtocolTDI)
	if err != nil {
		return finish(""), err
	}
	trace.SessionKey = sessionKeyTrace{
		Source: keySource,
		Length: len(sessionKey),
	}

	jsRequest, err := buildJsLoginRequest(appID, manualResult.SessionBlob, JSLoginTaskID, JSLoginTaskType)
	if err != nil {
		return finish(""), err
	}

	jsStage, err := longlink.SendPackedBody(ctx, PackedStage{
		Profile:      jsRequest.Profile,
		IdentityMode: "account",
		Body:         jsRequest.OutBody,
		Seq:          4,
		TaskID:       jsRequest.TaskID,
		TaskType:     jsRequest.TaskType,
		Timeout:      e.timeout,
	})
	if err != nil {
		return finish(""), err
	}

	jsDecoded := decodeJsLoginStage(jsStage, jsRequest, sessionKey)
	trace.JSLogin = jsLoginTrace{
		OK:                      jsDecoded.OK,
		Code:                    jsDecoded.Code,
		Ret:                     jsDecoded.Ret,
		ErrMsg:                  jsDecoded.ErrMsg,
		DecodeMode:              jsDecoded.DecodeMode,
		RequestBodyLen:          len(jsRequest.OutBody),
		ReplayDecryptsToWrapper: jsRequest.ReplayDecryptsToWrapper,
	}
	trace.JSLogin.AttemptCount, trace.JSLogin.EmptyBodies,
		trace.JSLogin.DecodeErrors, trace.JSLogin.DecodedWithoutCode, _ = summarizeJSLoginAttempts(jsDecoded.Attempts)
	if !jsDecoded.OK {
		return finish(""), fmt.Errorf(
			"js-login did not return code: %s",
			summarizeJSLoginFailure(jsDecoded.Attempts),
		)
	}

	return finish(jsDecoded.Code), nil
}

func (e *Engine) freshLoginBuffer(
	ctx context.Context,
	account model.Account,
) (model.Account, yyb.FreshLoginBuffer, error) {
	return e.credentials.FreshLoginBuffer(ctx, account.UnionID)
}

func applyFreshLoginBuffer(saved *session.SavedSession, fresh yyb.FreshLoginBuffer) {
	now := fresh.FetchedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	saved.SavedAt = now.Format(time.RFC3339Nano)
	saved.GUID = fresh.Credentials.GUID
	saved.UnionID = firstNonEmpty(fresh.Credentials.UnionID, saved.UnionID)
	saved.TokenInfo.OpenID = fresh.Credentials.OpenID
	saved.TokenInfo.AccessToken = fresh.Credentials.AccessToken
	saved.TokenInfo.RefreshToken = fresh.Credentials.RefreshToken
	saved.TokenInfo.LoginType = firstNonEmpty(fresh.Credentials.LoginType, saved.TokenInfo.LoginType, "WX")
	if fresh.Credentials.CookieExpiresAt != "" {
		saved.TokenInfo.CookieExpiresAt = fresh.Credentials.CookieExpiresAt
	}
	saved.LoginBufferInfo = session.LoginBufferInfo{
		GUID:         fresh.Credentials.GUID,
		OpenID:       fresh.Credentials.OpenID,
		AccessToken:  fresh.Credentials.AccessToken,
		RefreshToken: fresh.Credentials.RefreshToken,
		LoginType:    firstNonEmpty(fresh.Credentials.LoginType, saved.TokenInfo.LoginType, "WX"),
		LoginBuffer:  fresh.LoginBuffer.Raw,
		RefreshedAt:  now.Format(time.RFC3339Nano),
		Parsed: map[string]any{
			"authCode":   fresh.LoginBuffer.AuthCode,
			"ilinkAppId": fresh.LoginBuffer.IlinkAppID,
			"mpAppId":    fresh.LoginBuffer.MPAppID,
		},
	}
	if saved.ProtocolTDI == nil {
		saved.ProtocolTDI = map[string]any{}
	}
	saved.ProtocolTDI["username"] = firstNonEmpty(
		protocolTDIString(saved.ProtocolTDI, "username"),
		fresh.Credentials.OpenID+"@im."+IlinkAppID,
	)
	saved.ProtocolTDI["updatedAt"] = now.Format(time.RFC3339Nano)
}

func buildSavedSession(account model.Account) (session.SavedSession, error) {
	var saved session.SavedSession
	if err := json.Unmarshal([]byte(account.SavedSessionJSON), &saved); err != nil {
		return session.SavedSession{}, fmt.Errorf("decode account saved session json: %w", err)
	}

	saved.TokenInfo.AccessToken = account.AccessToken
	saved.TokenInfo.RefreshToken = account.RefreshToken
	saved.TokenInfo.OpenID = account.OpenID
	saved.TokenInfo.LoginType = account.LoginType
	saved.GUID = account.GUID
	saved.UnionID = account.UnionID
	saved.WXCode = account.WXCode
	saved.State = account.State
	saved.ProtocolDevice.AppDeviceID = account.AppDeviceID
	saved.ProtocolDevice.DeviceIDB64 = account.DeviceIDB64
	saved.ProtocolDevice.BoundGUID = account.GUID
	saved.ProtocolDevice.Source = firstNonEmpty(saved.ProtocolDevice.Source, "go-native")
	saved.ProtocolDevice.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)

	protocolTDI, err := tdi.MergeProtocolTDI(
		account.RawProtocolTDIJSON,
		tdi.Record{
			Username:          account.Username,
			UIN:               account.UIN,
			AutoAuthKeyB64:    account.AutoAuthKeyB64,
			AutoAuthEncKeyB64: account.AutoAuthEncKeyB64,
		},
	)
	if err != nil {
		return session.SavedSession{}, err
	}
	saved.ProtocolTDI = protocolTDI

	return saved, nil
}

func marshalTrace(trace exchangeTrace) string {
	return marshalJSON(trace)
}

func marshalJSON(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(payload)
}
