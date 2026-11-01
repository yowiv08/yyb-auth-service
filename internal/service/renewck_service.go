package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/store"
	"yyb-auth-service/internal/yyb"
)

const (
	renewCKTimeout      = 75 * time.Second
	renewCKPollTimeout  = 20 * time.Second
	renewCKPollInterval = 2 * time.Second
)

type RenewCKError struct {
	Code      string
	Stage     string
	Message   string
	WechatRet *int64
}

func (e *RenewCKError) Error() string { return e.Code + " stage=" + e.Stage + ": " + e.Message }

type RenewCKResult struct {
	OK         bool
	CKUpdated  bool
	UserInfoOK bool
	Account    model.Account
	Scope      string
}

type renewCKAccounts interface {
	ByUnionID(ctx context.Context, unionID string) (model.Account, error)
	upsertScannedSessionLocked(ctx context.Context, scanned ScannedOAuthSession) (model.Account, error)
}

type renewCKEngine interface {
	QRConnectAuthorize(ctx context.Context, account model.Account, uuid string) (native.QRConnectResult, error)
	QRConnectConfirm(ctx context.Context, account model.Account, uuid string) (native.QRConnectResult, error)
}

type renewCKClient interface {
	StartScan(ctx context.Context) (yyb.ScanInit, error)
	PollScan(ctx context.Context, uuid string, lastErrCode string) (yyb.ScanPollResult, error)
	ExchangeOAuth(ctx context.Context, guid string, code string) (yyb.OAuthResult, error)
	GetUserInfo(ctx context.Context, accessToken string, openID string, lang string) (yyb.UserInfo, error)
}

type RenewCKService struct {
	accounts     renewCKAccounts
	sessions     accountCoordinator
	engine       renewCKEngine
	client       renewCKClient
	logger       *slog.Logger
	timeout      time.Duration
	pollTimeout  time.Duration
	pollInterval time.Duration
}

func NewRenewCKService(accounts renewCKAccounts, sessions accountCoordinator, engine renewCKEngine, client renewCKClient, logger *slog.Logger) *RenewCKService {
	return &RenewCKService{
		accounts: accounts, sessions: sessions, engine: engine, client: client, logger: logger,
		timeout: renewCKTimeout, pollTimeout: renewCKPollTimeout, pollInterval: renewCKPollInterval,
	}
}

func (s *RenewCKService) Renew(ctx context.Context, unionID string) (result RenewCKResult, runErr error) {
	startedAt := time.Now()
	unionID = strings.TrimSpace(unionID)
	result.Account.UnionID = unionID
	defer func() { s.logResult(ctx, unionID, startedAt, result, runErr) }()
	if unionID == "" {
		return result, renewCKError("INVALID_REQUEST", "request", "unionid 必填")
	}
	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	unlock, err := s.sessions.LockOperation(runCtx, unionID)
	if err != nil {
		return result, renewCKUpstreamError("account", err)
	}
	defer unlock()
	account, err := s.accounts.ByUnionID(runCtx, unionID)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, store.ErrAccountNotFound) || errors.Is(err, ErrAccountNotFound) {
		return result, renewCKError("ACCOUNT_NOT_FOUND", "account", "unionid 对应账号不存在")
	}
	if err != nil {
		return result, renewCKError("CK_SAVE_FAILED", "account", "读取账号失败")
	}
	if !validRenewCKAccount(account) {
		return result, renewCKError("OLD_SESSION_INVALID", "account", "账号缺少有效的微信登录态，请重新扫码登录")
	}
	expectedOpenID := account.OpenID
	init, err := s.client.StartScan(runCtx)
	if err != nil {
		return result, renewCKUpstreamError("scan", err)
	}
	if strings.TrimSpace(init.UUID) == "" || strings.TrimSpace(init.GUID) == "" {
		return result, renewCKError("CK_RENEW_UPSTREAM_ERROR", "scan", "上游未返回有效的授权会话")
	}
	// StartScan sends GUID as the OAuth state; its separate State field is not
	// used by the upstream authorization URL.
	init.State = init.GUID
	authorized, err := s.engine.QRConnectAuthorize(runCtx, account, init.UUID)
	account, err = s.finishProtocolStep(runCtx, unionID, account, "authorize", authorized, err)
	if err != nil {
		return result, err
	}
	if !hasRenewCKScopes(authorized.ScopeList) {
		return result, renewCKError("CK_RENEW_UPSTREAM_ERROR", "authorize", "授权响应缺少应用宝所需权限")
	}
	if err := runCtx.Err(); err != nil {
		return result, renewCKUpstreamError("confirm", err)
	}
	// Confirmation may issue a one-use code. Finish the exchange despite a
	// disconnected caller, while preserving the original business deadline.
	deadline, _ := runCtx.Deadline()
	finishCtx, finishCancel := context.WithDeadline(context.WithoutCancel(runCtx), deadline)
	defer finishCancel()
	confirmed, err := s.engine.QRConnectConfirm(finishCtx, account, init.UUID)
	account, err = s.finishProtocolStep(finishCtx, unionID, account, "confirm", confirmed, err)
	if err != nil {
		return result, err
	}
	code, err := s.pollCode(finishCtx, init.UUID)
	if err != nil {
		return result, err
	}
	oauth, err := s.client.ExchangeOAuth(finishCtx, init.GUID, code)
	if err != nil {
		return result, renewCKUpstreamError("exchange", err)
	}
	if strings.TrimSpace(oauth.OpenID) == "" || strings.TrimSpace(oauth.AccessToken) == "" || strings.TrimSpace(oauth.RefreshToken) == "" {
		return result, renewCKError("CK_RENEW_UPSTREAM_ERROR", "exchange", "上游返回的新凭据不完整")
	}
	if oauth.OpenID != expectedOpenID {
		return result, renewCKError("ACCOUNT_MISMATCH", "exchange", "兑换出的凭据与原账号不匹配")
	}
	persistCtx, persistCancel := persistenceContext(finishCtx)
	_, err = s.accounts.upsertScannedSessionLocked(persistCtx, ScannedOAuthSession{
		UnionID: unionID, OpenID: oauth.OpenID, AccessToken: oauth.AccessToken, RefreshToken: oauth.RefreshToken,
		GUID: init.GUID, State: init.State, WXCode: code, CookieExpiresAt: oauth.CookieExpiresAt, LoginType: "WX",
	})
	if err != nil {
		persistCancel()
		return result, renewCKError("CK_SAVE_FAILED", "save", "保存新 CK 失败")
	}
	result.CKUpdated = true
	result.Scope = native.QRConnectScope
	account, err = s.accounts.ByUnionID(persistCtx, unionID)
	persistCancel()
	if err != nil {
		return result, renewCKError("CK_SAVE_FAILED", "save", "新 CK 已保存，读取保存结果失败")
	}
	if account.OpenID != expectedOpenID || account.AccessToken != oauth.AccessToken || account.RefreshToken != oauth.RefreshToken || account.GUID != init.GUID {
		return result, renewCKError("CK_SAVE_FAILED", "save", "新 CK 的保存结果不一致")
	}
	result.Account = account
	user, err := s.client.GetUserInfo(finishCtx, account.AccessToken, account.OpenID, "zh_CN")
	if err != nil || user.ErrCode != 0 || user.OpenID != expectedOpenID || user.UnionID != unionID {
		validationErr := renewCKError("CK_VALIDATION_FAILED", "userinfo", "新 CK 已保存，用户信息校验失败")
		if err == nil && user.ErrCode != 0 {
			ret := int64(user.ErrCode)
			validationErr.WechatRet = &ret
		}
		return result, validationErr
	}
	result.OK, result.UserInfoOK = true, true
	return result, nil
}

func (s *RenewCKService) finishProtocolStep(ctx context.Context, unionID string, account model.Account, stage string, result native.QRConnectResult, runErr error) (model.Account, error) {
	if shouldSyncSavedSession(result.UpdatedSavedSession) {
		persistCtx, cancel := persistenceContext(ctx)
		updated, err := s.sessions.MergeSession(persistCtx, unionID, result.UpdatedSavedSession)
		cancel()
		if err != nil {
			return account, renewCKError("CK_SAVE_FAILED", stage, "保存授权登录态失败")
		}
		account = updated
	}
	if runErr != nil {
		return account, renewCKUpstreamError(stage, runErr)
	}
	if !result.OK {
		err := renewCKError("QRCONNECT_REJECTED", stage, "微信拒绝应用宝授权")
		ret := result.Ret
		err.WechatRet = &ret
		return account, err
	}
	return account, nil
}

func (s *RenewCKService) pollCode(ctx context.Context, uuid string) (string, error) {
	pollCtx, cancel := context.WithTimeout(ctx, s.pollTimeout)
	defer cancel()
	last := ""
	for {
		poll, err := s.client.PollScan(pollCtx, uuid, last)
		if err != nil {
			return "", renewCKUpstreamError("poll", err)
		}
		if poll.ErrCode == "405" && strings.TrimSpace(poll.WXCode) != "" {
			return poll.WXCode, nil
		}
		switch poll.ErrCode {
		case "403", "402":
			return "", renewCKError("QRCONNECT_REJECTED", "poll", "授权会话已取消或过期")
		case "404", "408":
			last = poll.ErrCode
		default:
			return "", renewCKError("CK_RENEW_UPSTREAM_ERROR", "poll", "上游未返回有效的授权 code")
		}
		timer := time.NewTimer(s.pollInterval)
		select {
		case <-pollCtx.Done():
			timer.Stop()
			return "", renewCKUpstreamError("poll", pollCtx.Err())
		case <-timer.C:
		}
	}
}

func validRenewCKAccount(account model.Account) bool {
	return strings.TrimSpace(account.OpenID) != "" && strings.TrimSpace(account.AccessToken) != "" &&
		strings.TrimSpace(account.RefreshToken) != "" && strings.TrimSpace(account.GUID) != "" &&
		strings.TrimSpace(account.DeviceIDB64) != "" && strings.TrimSpace(account.AppDeviceID) != "" &&
		(account.LoginType == "" || account.LoginType == "WX") && json.Valid([]byte(account.SavedSessionJSON))
}

func hasRenewCKScopes(scopes []string) bool {
	login, runtime := false, false
	for _, scope := range scopes {
		login = login || scope == "snsapi_login"
		runtime = runtime || scope == "snsapi_runtime_pcsdk"
	}
	return login && runtime
}

func renewCKError(code, stage, message string) *RenewCKError {
	return &RenewCKError{Code: code, Stage: stage, Message: message}
}

func renewCKUpstreamError(stage string, err error) *RenewCKError {
	if yyb.IsCredentialExpired(err) || errors.Is(err, native.ErrOAuthSessionExpired) {
		return renewCKError("OLD_SESSION_INVALID", stage, "旧登录态已失效，请重新扫码登录")
	}
	var timeoutErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || (errors.As(err, &timeoutErr) && timeoutErr.Timeout()) {
		return renewCKError("CK_RENEW_TIMEOUT", stage, "换新 CK 请求超时或已取消")
	}
	return renewCKError("CK_RENEW_UPSTREAM_ERROR", stage, "换新 CK 的上游请求失败")
}

func (s *RenewCKService) logResult(ctx context.Context, unionID string, startedAt time.Time, result RenewCKResult, err error) {
	if s.logger == nil {
		return
	}
	attrs := []slog.Attr{slog.String("unionid", unionID), slog.Bool("ok", result.OK), slog.Bool("ck_updated", result.CKUpdated), slog.Int64("duration_ms", time.Since(startedAt).Milliseconds())}
	level := slog.LevelInfo
	var renewalErr *RenewCKError
	if errors.As(err, &renewalErr) {
		level = slog.LevelError
		attrs = append(attrs, slog.String("error_code", renewalErr.Code), slog.String("stage", renewalErr.Stage))
		if renewalErr.WechatRet != nil {
			attrs = append(attrs, slog.Int64("wechat_ret", *renewalErr.WechatRet))
		}
	}
	s.logger.LogAttrs(ctx, level, "应用宝 CK 换新完成", attrs...)
}
