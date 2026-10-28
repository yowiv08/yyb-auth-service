package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/store"
)

const (
	oauthRunTimeout                 = 75 * time.Second
	oauthStateMaxLength             = 128
	oauthURLMaxLength               = 8192
	OAuthStatusConfirmationRequired = "confirmation_required"
	OAuthStatusCompleted            = "completed"
)

var (
	ErrOAuthAccountNotFound = errors.New("oauth account not found")
	oauthAppIDPattern       = regexp.MustCompile(`^wx[0-9a-fA-F]{16}$`)
	oauthStatePattern       = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

type OAuthValidationError struct {
	Message string
}

func (e *OAuthValidationError) Error() string { return e.Message }

type OAuthBusinessError struct {
	Ret     int64
	Message string
}

func (e *OAuthBusinessError) Error() string {
	return fmt.Sprintf("wechat oauth rejected ret=%d message=%s", e.Ret, e.Message)
}

type OAuthUpstreamError struct {
	Err error
}

func (e *OAuthUpstreamError) Error() string { return e.Err.Error() }
func (e *OAuthUpstreamError) Unwrap() error { return e.Err }

type OAuthAuthorizeRequest struct {
	UnionID     string
	AppID       string
	RedirectURI string
	Scope       string
	State       string
	BizUsername string
	Scene       int
	ReferrerURL string
	SubScene    *int
	AutoOAuth   *bool
}

type OAuthConfirmRequest struct {
	UnionID          string
	AppID            string
	AuthorizationURL string
	AvatarID         string
}

type OAuthAuthorizeResult struct {
	Status           string
	UnionID          string
	AppID            string
	Scope            string
	State            string
	AuthorizationURL string
	Code             string
	IsRecentHasAuth  bool
	IsSilentAuth     bool
	ScopeList        []native.OAuthScopeInfo
	AvatarList       []native.OAuthAvatarInfo
}

type OAuthConfirmResult struct {
	Status      string
	UnionID     string
	AppID       string
	Code        string
	State       string
	RedirectURI string
}

type oauthCoordinator interface {
	accountCoordinator
	RecoverExpired(
		ctx context.Context,
		unionID string,
		rejectedAccessToken string,
	) (model.Account, error)
}

type OAuthService struct {
	accounts *store.AccountStore
	engine   *native.Engine
	sessions oauthCoordinator
	logger   *slog.Logger
}

type oauthAuthorizationMetadata struct {
	AppID       string
	Scope       string
	State       string
	RedirectURI string
}

func NewOAuthService(
	accounts *store.AccountStore,
	engine *native.Engine,
	sessions oauthCoordinator,
	logger *slog.Logger,
) *OAuthService {
	return &OAuthService{accounts: accounts, engine: engine, sessions: sessions, logger: logger}
}

func (s *OAuthService) Authorize(
	ctx context.Context,
	input OAuthAuthorizeRequest,
) (OAuthAuthorizeResult, error) {
	startedAt := time.Now()
	prepared, authorizationURL, err := prepareOAuthAuthorizeRequest(input)
	if err != nil {
		return OAuthAuthorizeResult{}, err
	}
	s.logInfo(ctx, "公众号 OAuth 授权开始",
		slog.String("unionid", prepared.UnionID),
		slog.String("appid", prepared.AppID),
		slog.String("scope", prepared.Scope),
	)

	oauthCtx, cancel := context.WithTimeout(ctx, oauthRunTimeout)
	defer cancel()
	unlock, err := s.sessions.LockOperation(oauthCtx, prepared.UnionID)
	if err != nil {
		return OAuthAuthorizeResult{}, &OAuthUpstreamError{Err: fmt.Errorf("lock account operation: %w", err)}
	}
	defer unlock()

	account, err := s.account(prepared.UnionID, oauthCtx)
	if err != nil {
		return OAuthAuthorizeResult{}, err
	}
	nativeInput := native.OAuthAuthorizeInput{
		AppID: prepared.AppID, AuthorizationURL: authorizationURL,
		BizUsername: prepared.BizUsername, Scene: prepared.Scene,
		ReferrerURL: prepared.ReferrerURL, SubScene: prepared.SubScene,
		AutoOAuth: prepared.AutoOAuth,
	}
	result, runErr := s.engine.OAuthAuthorize(oauthCtx, account, nativeInput)
	result, runErr = s.retryOAuthOnce(oauthCtx, account, result, runErr, func(refreshed model.Account) (native.OAuthResult, error) {
		return s.engine.OAuthAuthorize(oauthCtx, refreshed, nativeInput)
	})
	if syncErr := s.syncSession(ctx, prepared.UnionID, result); syncErr != nil && runErr == nil {
		runErr = syncErr
	}
	if runErr != nil {
		err = &OAuthUpstreamError{Err: runErr}
		s.logError(ctx, "公众号 OAuth 授权失败", err, startedAt,
			slog.String("unionid", prepared.UnionID), slog.String("appid", prepared.AppID))
		return OAuthAuthorizeResult{}, err
	}
	if !result.OK {
		err = &OAuthBusinessError{Ret: result.Ret, Message: firstNonEmpty(result.ErrMsg, "unknown")}
		s.logError(ctx, "公众号 OAuth 授权被拒绝", err, startedAt,
			slog.String("unionid", prepared.UnionID), slog.String("appid", prepared.AppID))
		return OAuthAuthorizeResult{}, err
	}
	code, redirectState, parseErr := parseOAuthRedirect(result.RedirectURL)
	if parseErr != nil {
		s.logError(ctx, "公众号 OAuth redirect 解析失败", parseErr, startedAt,
			slog.String("redirect_url", result.RedirectURL),
			slog.String("unionid", prepared.UnionID), slog.String("appid", prepared.AppID))
		return OAuthAuthorizeResult{}, &OAuthUpstreamError{Err: fmt.Errorf("parse oauth redirect: %w", parseErr)}
	}
	state := prepared.State
	status := OAuthStatusConfirmationRequired
	responseURL := authorizationURL
	if code != "" {
		if redirectState != prepared.State {
			return OAuthAuthorizeResult{}, &OAuthUpstreamError{Err: fmt.Errorf("oauth redirect state mismatch")}
		}
		status = OAuthStatusCompleted
		state = redirectState
		responseURL = ""
	} else if strings.TrimSpace(result.RedirectURL) != "" {
		metadata, validateErr := validateAuthorizationURL(result.RedirectURL, prepared.AppID)
		if validateErr == nil && metadata.State == prepared.State && metadata.Scope == prepared.Scope &&
			metadata.RedirectURI == prepared.RedirectURI {
			responseURL = result.RedirectURL
		}
	}

	out := OAuthAuthorizeResult{
		Status: status, UnionID: prepared.UnionID, AppID: prepared.AppID,
		Scope: prepared.Scope, State: state, AuthorizationURL: responseURL, Code: code,
		IsRecentHasAuth: result.IsRecentHasAuth, IsSilentAuth: result.IsSilentAuth,
		ScopeList: nonNilOAuthScopes(result.ScopeList), AvatarList: nonNilOAuthAvatars(result.AvatarList),
	}
	s.logInfo(ctx, "公众号 OAuth 授权完成",
		slog.String("unionid", prepared.UnionID), slog.String("appid", prepared.AppID),
		slog.String("status", status), slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()))
	return out, nil
}

func (s *OAuthService) Confirm(
	ctx context.Context,
	input OAuthConfirmRequest,
) (OAuthConfirmResult, error) {
	startedAt := time.Now()
	unionID := strings.TrimSpace(input.UnionID)
	if unionID == "" {
		return OAuthConfirmResult{}, validationError("unionid 必填")
	}
	appID, err := validateOAuthAppID(input.AppID)
	if err != nil {
		return OAuthConfirmResult{}, err
	}
	metadata, err := validateAuthorizationURL(input.AuthorizationURL, appID)
	if err != nil {
		return OAuthConfirmResult{}, err
	}
	avatarID := strings.TrimSpace(input.AvatarID)
	if avatarID != "" {
		if _, err := strconv.ParseUint(avatarID, 10, 31); err != nil {
			return OAuthConfirmResult{}, validationError("avatar_id 必须是非负 32 位整数文本")
		}
	}
	s.logInfo(ctx, "公众号 OAuth 确认授权开始",
		slog.String("unionid", unionID), slog.String("appid", appID), slog.String("scope", metadata.Scope))

	oauthCtx, cancel := context.WithTimeout(ctx, oauthRunTimeout)
	defer cancel()
	unlock, err := s.sessions.LockOperation(oauthCtx, unionID)
	if err != nil {
		return OAuthConfirmResult{}, &OAuthUpstreamError{Err: fmt.Errorf("lock account operation: %w", err)}
	}
	defer unlock()
	account, err := s.account(unionID, oauthCtx)
	if err != nil {
		return OAuthConfirmResult{}, err
	}
	nativeInput := native.OAuthConfirmInput{
		AppID: appID, AuthorizationURL: strings.TrimSpace(input.AuthorizationURL),
		AvatarID: avatarID,
	}
	result, runErr := s.engine.OAuthConfirm(oauthCtx, account, nativeInput)
	result, runErr = s.retryOAuthOnce(oauthCtx, account, result, runErr, func(refreshed model.Account) (native.OAuthResult, error) {
		return s.engine.OAuthConfirm(oauthCtx, refreshed, nativeInput)
	})
	if syncErr := s.syncSession(ctx, unionID, result); syncErr != nil && runErr == nil {
		runErr = syncErr
	}
	if runErr != nil {
		err = &OAuthUpstreamError{Err: runErr}
		s.logError(ctx, "公众号 OAuth 确认授权失败", err, startedAt,
			slog.String("unionid", unionID), slog.String("appid", appID))
		return OAuthConfirmResult{}, err
	}
	if !result.OK {
		err = &OAuthBusinessError{Ret: result.Ret, Message: firstNonEmpty(result.ErrMsg, "unknown")}
		s.logError(ctx, "公众号 OAuth 确认授权被拒绝", err, startedAt,
			slog.String("unionid", unionID), slog.String("appid", appID))
		return OAuthConfirmResult{}, err
	}
	code, state, parseErr := parseOAuthRedirect(result.RedirectURL)
	if parseErr != nil {
		return OAuthConfirmResult{}, &OAuthUpstreamError{Err: fmt.Errorf("parse oauth confirm redirect: %w", parseErr)}
	}
	if code == "" {
		return OAuthConfirmResult{}, &OAuthUpstreamError{Err: fmt.Errorf("oauth confirm response missing code")}
	}
	if state != metadata.State {
		return OAuthConfirmResult{}, &OAuthUpstreamError{Err: fmt.Errorf("oauth confirm state mismatch")}
	}
	out := OAuthConfirmResult{
		Status: OAuthStatusCompleted, UnionID: unionID, AppID: appID,
		Code: code, State: state, RedirectURI: metadata.RedirectURI,
	}
	s.logInfo(ctx, "公众号 OAuth 确认授权完成",
		slog.String("unionid", unionID), slog.String("appid", appID),
		slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()))
	return out, nil
}

func prepareOAuthAuthorizeRequest(
	input OAuthAuthorizeRequest,
) (OAuthAuthorizeRequest, string, error) {
	input.UnionID = strings.TrimSpace(input.UnionID)
	if input.UnionID == "" {
		return OAuthAuthorizeRequest{}, "", validationError("unionid 必填")
	}
	appID, err := validateOAuthAppID(input.AppID)
	if err != nil {
		return OAuthAuthorizeRequest{}, "", err
	}
	redirectURI, err := validateRedirectURI(input.RedirectURI)
	if err != nil {
		return OAuthAuthorizeRequest{}, "", err
	}
	scope, err := validateOAuthScope(input.Scope)
	if err != nil {
		return OAuthAuthorizeRequest{}, "", err
	}
	state := strings.TrimSpace(input.State)
	if state == "" {
		state, err = generateOAuthState()
		if err != nil {
			return OAuthAuthorizeRequest{}, "", &OAuthUpstreamError{Err: err}
		}
	}
	if err := validateOAuthState(state); err != nil {
		return OAuthAuthorizeRequest{}, "", err
	}
	if input.Scene < 0 {
		return OAuthAuthorizeRequest{}, "", validationError("scene 必须大于或等于 0")
	}
	if input.SubScene != nil && *input.SubScene < 0 {
		return OAuthAuthorizeRequest{}, "", validationError("sub_scene 必须大于或等于 0")
	}
	referrerURL := strings.TrimSpace(input.ReferrerURL)
	if referrerURL != "" {
		if _, err := validateAbsoluteHTTPURL(referrerURL, "referrer_url"); err != nil {
			return OAuthAuthorizeRequest{}, "", err
		}
	}
	input.AppID = appID
	input.RedirectURI = redirectURI
	input.Scope = scope
	input.State = state
	input.BizUsername = strings.TrimSpace(input.BizUsername)
	input.ReferrerURL = referrerURL

	query := url.Values{}
	query.Set("appid", appID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", scope)
	query.Set("state", state)
	authorizationURL := (&url.URL{
		Scheme: "https", Host: "open.weixin.qq.com", Path: "/connect/oauth2/authorize",
		RawQuery: query.Encode(), Fragment: "wechat_redirect",
	}).String()
	return input, authorizationURL, nil
}

func validateAuthorizationURL(raw string, expectedAppID string) (oauthAuthorizationMetadata, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return oauthAuthorizationMetadata{}, validationError("authorization_url 必填")
	}
	if len(raw) > oauthURLMaxLength {
		return oauthAuthorizationMetadata{}, validationError("authorization_url 过长")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return oauthAuthorizationMetadata{}, validationError("authorization_url 非法")
	}
	if parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), "open.weixin.qq.com") ||
		parsed.Path != "/connect/oauth2/authorize" || parsed.Fragment != "wechat_redirect" {
		return oauthAuthorizationMetadata{}, validationError("authorization_url 必须是微信公众平台授权地址")
	}
	query := parsed.Query()
	appID, err := validateOAuthAppID(query.Get("appid"))
	if err != nil || appID != expectedAppID {
		return oauthAuthorizationMetadata{}, validationError("authorization_url 中的 appid 不匹配")
	}
	if query.Get("response_type") != "code" {
		return oauthAuthorizationMetadata{}, validationError("authorization_url response_type 必须是 code")
	}
	scope, err := validateOAuthScope(query.Get("scope"))
	if err != nil {
		return oauthAuthorizationMetadata{}, err
	}
	state := query.Get("state")
	if err := validateOAuthState(state); err != nil {
		return oauthAuthorizationMetadata{}, err
	}
	redirectURI, err := validateRedirectURI(query.Get("redirect_uri"))
	if err != nil {
		return oauthAuthorizationMetadata{}, err
	}
	if query.Get("code") != "" {
		return oauthAuthorizationMetadata{}, validationError("authorization_url 不得包含 code")
	}
	return oauthAuthorizationMetadata{AppID: appID, Scope: scope, State: state, RedirectURI: redirectURI}, nil
}

func validateOAuthAppID(raw string) (string, error) {
	appID := strings.TrimSpace(raw)
	if !oauthAppIDPattern.MatchString(appID) {
		return "", validationError("appid 格式非法")
	}
	return appID, nil
}

func validateOAuthScope(raw string) (string, error) {
	scope := strings.TrimSpace(raw)
	if scope != "snsapi_base" && scope != "snsapi_userinfo" {
		return "", validationError("scope 只允许 snsapi_base 或 snsapi_userinfo")
	}
	return scope, nil
}

func validateOAuthState(state string) error {
	if state == "" {
		return validationError("state 必填")
	}
	if len(state) > oauthStateMaxLength || !oauthStatePattern.MatchString(state) {
		return validationError("state 仅允许 A-Z、a-z、0-9、点、下划线、波浪线和连字符，且最长 128 字符")
	}
	return nil
}

func validateRedirectURI(raw string) (string, error) {
	parsed, err := validateAbsoluteHTTPURL(strings.TrimSpace(raw), "redirect_uri")
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func validateAbsoluteHTTPURL(raw string, field string) (*url.URL, error) {
	if raw == "" {
		return nil, validationError(field + " 必填")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" {
		return nil, validationError(field + " 必须是绝对 HTTP/HTTPS URL")
	}
	return parsed, nil
}

func generateOAuthState() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate oauth state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func parseOAuthRedirect(raw string) (string, string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", "", nil
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", fmt.Errorf("invalid redirect url")
	}
	return parsed.Query().Get("code"), parsed.Query().Get("state"), nil
}

func (s *OAuthService) retryOAuthOnce(
	ctx context.Context,
	account model.Account,
	result native.OAuthResult,
	runErr error,
	retry func(model.Account) (native.OAuthResult, error),
) (native.OAuthResult, error) {
	if !errors.Is(runErr, native.ErrOAuthSessionExpired) {
		return result, runErr
	}
	rejectedAccessToken := account.AccessToken
	if token := strings.TrimSpace(result.UpdatedSavedSession.TokenInfo.AccessToken); token != "" {
		rejectedAccessToken = token
	}
	refreshed, err := s.sessions.RecoverExpired(ctx, account.UnionID, rejectedAccessToken)
	if err != nil {
		return result, errors.Join(runErr, fmt.Errorf("refresh oauth session credentials: %w", err))
	}
	return retry(refreshed)
}

func (s *OAuthService) account(unionID string, ctx context.Context) (model.Account, error) {
	account, err := s.accounts.ByUnionID(ctx, unionID)
	if errors.Is(err, store.ErrAccountNotFound) || errors.Is(err, sql.ErrNoRows) {
		return model.Account{}, fmt.Errorf("%w: %s", ErrOAuthAccountNotFound, unionID)
	}
	if err != nil {
		return model.Account{}, &OAuthUpstreamError{Err: err}
	}
	return account, nil
}

func (s *OAuthService) syncSession(ctx context.Context, unionID string, result native.OAuthResult) error {
	if !shouldSyncSavedSession(result.UpdatedSavedSession) {
		return nil
	}
	syncCtx, cancel := persistenceContext(ctx)
	defer cancel()
	_, err := s.sessions.MergeSession(syncCtx, unionID, result.UpdatedSavedSession)
	if err != nil {
		return fmt.Errorf("persist oauth session: %w", err)
	}
	return nil
}

func nonNilOAuthScopes(values []native.OAuthScopeInfo) []native.OAuthScopeInfo {
	if values == nil {
		return []native.OAuthScopeInfo{}
	}
	return values
}

func nonNilOAuthAvatars(values []native.OAuthAvatarInfo) []native.OAuthAvatarInfo {
	if values == nil {
		return []native.OAuthAvatarInfo{}
	}
	return values
}

func validationError(message string) error { return &OAuthValidationError{Message: message} }

func (s *OAuthService) logInfo(ctx context.Context, msg string, attrs ...slog.Attr) {
	if s.logger != nil {
		s.logger.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
	}
}

func (s *OAuthService) logError(
	ctx context.Context,
	msg string,
	err error,
	startedAt time.Time,
	attrs ...slog.Attr,
) {
	if s.logger == nil {
		return
	}
	attrs = append(attrs, slog.Any("error", err), slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()))
	s.logger.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}
