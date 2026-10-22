package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/service"
)

type Server struct {
	accountService  *service.AccountService
	exchangeService *service.ExchangeService
	cloudService    *service.CloudService
	scanService     *service.ScanService
	userInfoService *service.UserInfoService
	oauthService    *service.OAuthService
	logger          *slog.Logger
	bearerToken     string
}

const (
	operateWXDataTypeRaw                = 1
	operateWXDataTypeCloudFunction      = 2
	operateWXDataTypeGatewayServiceInfo = 3
)

type operateWXDataPreparedData struct {
	DataString                string
	GatewayServiceInfoRequest *gatewayServiceInfoRequest
}

type gatewayServiceInfoRequest struct {
	RID              string
	Source           string
	ClientKX         string
	ClientPrivateKey string
}

func NewServer(
	accountService *service.AccountService,
	exchangeService *service.ExchangeService,
	cloudService *service.CloudService,
	scanService *service.ScanService,
	userInfoService *service.UserInfoService,
	oauthService *service.OAuthService,
	logger *slog.Logger,
	bearerToken string,
) *Server {
	return &Server{
		accountService:  accountService,
		exchangeService: exchangeService,
		cloudService:    cloudService,
		scanService:     scanService,
		userInfoService: userInfoService,
		oauthService:    oauthService,
		logger:          logger,
		bearerToken:     bearerToken,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleSwaggerUI)
	mux.HandleFunc("/openapi.json", s.handleOpenAPI)
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/code", s.handleCode)
	mux.HandleFunc("/api/operatewxdata", s.handleOperateWXData)
	mux.HandleFunc("/api/getuserinfo", s.handleGetUserInfo)
	mux.HandleFunc("/api/oauthauthorize", s.handleOAuthAuthorize)
	mux.HandleFunc("/api/oauthconfirm", s.handleOAuthConfirm)
	mux.HandleFunc("/api/getphone", s.handleGetPhone)
	mux.HandleFunc("/api/transfer", s.handleTransfer)
	mux.HandleFunc("/api/scan", s.handleScan)
	return loggingMiddleware(s.logger, s.authMiddleware(mux))
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listUsers(w, r)
	case http.MethodPost:
		s.deleteUser(w, r)
	default:
		writeMethodNotAllowed(w, "GET or POST")
	}
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.accountService.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, makeUserResponses(accounts))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UnionID string `json:"unionid"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	unionID, err := requiredString(body.UnionID, "unionid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := s.accountService.Delete(r.Context(), unionID)
	if err != nil {
		if errors.Is(err, service.ErrAccountNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, makeDeleteUserResponse(result))
}

func (s *Server) handleCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}

	var body struct {
		UnionID string `json:"unionid"`
		AppID   string `json:"appid"`
		Type    *int   `json:"type"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	unionID, err := requiredString(body.UnionID, "unionid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	appID, err := requiredString(body.AppID, "appid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Type == nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("type 必填"))
		return
	}
	if *body.Type != service.CodeTypeLegacy && *body.Type != service.CodeTypeHTTP {
		writeError(w, http.StatusBadRequest, fmt.Errorf("type 必须是 1 或 2"))
		return
	}

	run, err := s.exchangeService.ExchangeCode(r.Context(), unionID, appID, *body.Type)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, makeCodeResultResponse(run))
}

func (s *Server) handleOperateWXData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	startedAt := time.Now()

	var body struct {
		UnionID      string          `json:"unionid"`
		AppID        string          `json:"appid"`
		Type         *int            `json:"type"`
		OperateCode  *int            `json:"operate_code"`
		FunctionName string          `json:"function_name"`
		Data         json.RawMessage `json:"data"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	unionID, err := requiredString(body.UnionID, "unionid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	appID, err := requiredString(body.AppID, "appid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Type == nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("type 必填"))
		return
	}
	requestType := *body.Type
	if requestType != operateWXDataTypeRaw &&
		requestType != operateWXDataTypeCloudFunction &&
		requestType != operateWXDataTypeGatewayServiceInfo {
		writeError(w, http.StatusBadRequest, fmt.Errorf("type 必须是 1、2 或 3"))
		return
	}
	operateCode := operateWXDataCode(body.OperateCode)
	if operateCode < 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("operate_code 必须大于或等于 0"))
		return
	}
	if len(body.Data) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("data 必填"))
		return
	}

	prepared, err := prepareOperateWXDataData(
		requestType,
		body.FunctionName,
		body.Data,
		time.Now(),
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := s.cloudService.OperateWXData(
		r.Context(),
		unionID,
		appID,
		operateCode,
		prepared.DataString,
		operateWXDataMode(requestType),
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		makeOperateWXDataResponse(
			result,
			time.Since(startedAt),
			prepared.GatewayServiceInfoRequest,
		),
	)
}

func (s *Server) handleGetUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	startedAt := time.Now()

	var body struct {
		UnionID string `json:"unionid"`
		Lang    string `json:"lang"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	unionID, err := requiredString(body.UnionID, "unionid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := s.userInfoService.Get(r.Context(), unionID, body.Lang)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, makeUserInfoResponse(result, time.Since(startedAt)))
}

func (s *Server) handleGetPhone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	startedAt := time.Now()

	var body struct {
		UnionID string `json:"unionid"`
		AppID   string `json:"appid"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	unionID, err := requiredString(body.UnionID, "unionid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	appID, err := requiredString(body.AppID, "appid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := s.cloudService.GetPhoneNumber(r.Context(), unionID, appID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, makePhoneResponse(result, time.Since(startedAt)))
}

func (s *Server) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	startedAt := time.Now()
	var body struct {
		UnionID     string `json:"unionid"`
		AppID       string `json:"appid"`
		RedirectURI string `json:"redirect_uri"`
		Scope       string `json:"scope"`
		State       string `json:"state"`
		BizUsername string `json:"biz_username"`
		Scene       int    `json:"scene"`
		ReferrerURL string `json:"referrer_url"`
		SubScene    *int   `json:"sub_scene"`
		AutoOAuth   *bool  `json:"auto_oauth"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeOAuthError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.oauthService.Authorize(r.Context(), service.OAuthAuthorizeRequest{
		UnionID: body.UnionID, AppID: body.AppID, RedirectURI: body.RedirectURI,
		Scope: body.Scope, State: body.State, BizUsername: body.BizUsername,
		Scene: body.Scene, ReferrerURL: body.ReferrerURL, SubScene: body.SubScene,
		AutoOAuth: body.AutoOAuth,
	})
	if err != nil {
		writeOAuthServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, makeOAuthAuthorizeResponse(result, time.Since(startedAt)))
}

func (s *Server) handleOAuthConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	startedAt := time.Now()
	var body struct {
		UnionID          string `json:"unionid"`
		AppID            string `json:"appid"`
		AuthorizationURL string `json:"authorization_url"`
		AvatarID         string `json:"avatar_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeOAuthError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.oauthService.Confirm(r.Context(), service.OAuthConfirmRequest{
		UnionID: body.UnionID, AppID: body.AppID,
		AuthorizationURL: body.AuthorizationURL, AvatarID: body.AvatarID,
	})
	if err != nil {
		writeOAuthServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, makeOAuthConfirmResponse(result, time.Since(startedAt)))
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createScan(w, r)
	case http.MethodGet:
		s.getScan(w, r)
	default:
		writeMethodNotAllowed(w, "GET 或 POST")
	}
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	scan, err := s.scanService.Start(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	writeJSON(w, http.StatusOK, makeScanSessionResponse(scan, time.Now().UTC()))
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	scanID, err := scanIDFromQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	scan, err := s.scanService.Get(r.Context(), scanID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}

	writeJSON(w, http.StatusOK, makeScanSessionResponse(scan, time.Now().UTC()))
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requiresBearerAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if bearerTokenMatches(r.Header.Get("Authorization"), s.bearerToken) {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
	})
}

func requiresBearerAuth(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

func bearerTokenMatches(header string, token string) bool {
	const prefix = "Bearer "
	if token == "" || !strings.HasPrefix(header, prefix) {
		return false
	}

	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func requiredString(value string, name string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%s 必填", name)
	}
	return trimmed, nil
}

func scanIDFromQuery(r *http.Request) (int64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	if raw == "" {
		return 0, fmt.Errorf("scan_id 必填")
	}

	scanID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || scanID <= 0 {
		return 0, fmt.Errorf("scan_id 非法")
	}
	return scanID, nil
}

func decodeJSON(r *http.Request, target any) error {
	const requestBodyLimit = 16 << 20
	if r.Body == nil {
		return fmt.Errorf("decode json: empty request body")
	}
	defer r.Body.Close()
	if r.ContentLength > requestBodyLimit {
		return fmt.Errorf("decode json: request body exceeds %d bytes", requestBodyLimit)
	}
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, requestBodyLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return fmt.Errorf("decode json: %w", err)
		}
		return fmt.Errorf("decode json: request body must contain a single JSON value")
	}
	return nil
}

func operateWXDataString(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text, nil
	}

	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return "", fmt.Errorf("compact operatewxdata data: %w", err)
	}
	return compact.String(), nil
}

func prepareOperateWXDataData(
	requestType int,
	functionName string,
	raw json.RawMessage,
	now time.Time,
) (operateWXDataPreparedData, error) {
	switch requestType {
	case operateWXDataTypeRaw:
		dataString, err := operateWXDataString(raw)
		if err != nil {
			return operateWXDataPreparedData{}, err
		}
		return operateWXDataPreparedData{DataString: dataString}, nil
	case operateWXDataTypeCloudFunction:
		dataString, err := buildQBaseCallFunctionData(functionName, raw, now)
		if err != nil {
			return operateWXDataPreparedData{}, err
		}
		return operateWXDataPreparedData{DataString: dataString}, nil
	case operateWXDataTypeGatewayServiceInfo:
		return buildQBaseGatewayServiceInfoData(raw, now)
	default:
		return operateWXDataPreparedData{}, fmt.Errorf("type 必须是 1、2 或 3")
	}
}

func buildQBaseCallFunctionData(
	functionName string,
	rawData json.RawMessage,
	now time.Time,
) (string, error) {
	functionName = strings.TrimSpace(functionName)
	if functionName == "" {
		return "", fmt.Errorf("function_name 必填")
	}

	dataString, err := operateWXDataString(rawData)
	if err != nil {
		return "", fmt.Errorf("encode function data: %w", err)
	}

	currentTime := now.UnixMilli()
	randomValue, err := randomDecimalString()
	if err != nil {
		return "", err
	}
	cliRandomValue, err := randomDecimalString()
	if err != nil {
		return "", err
	}

	qbaseReq := struct {
		FunctionName string   `json:"function_name"`
		Data         string   `json:"data"`
		Action       int      `json:"action"`
		Scene        int      `json:"scene"`
		CallID       string   `json:"call_id"`
		CloudIDList  []string `json:"cloudid_list"`
	}{
		FunctionName: functionName,
		Data:         dataString,
		Action:       1,
		Scene:        1,
		CallID:       fmt.Sprintf("%d-%s", currentTime, randomValue),
		CloudIDList:  []string{},
	}
	qbaseReqPayload, err := json.Marshal(qbaseReq)
	if err != nil {
		return "", fmt.Errorf("encode qbase_req: %w", err)
	}

	payload := struct {
		APIName         string `json:"api_name"`
		Data            any    `json:"data"`
		OperateDirectly bool   `json:"operate_directly"`
	}{
		APIName: "qbase_commapi",
		Data: struct {
			CLIReqID     string         `json:"cli_req_id"`
			QBaseAPIName string         `json:"qbase_api_name"`
			QBaseMeta    map[string]any `json:"qbase_meta"`
			QBaseOptions map[string]any `json:"qbase_options"`
			QBaseReq     string         `json:"qbase_req"`
		}{
			CLIReqID:     fmt.Sprintf("%d_%s", currentTime, cliRandomValue),
			QBaseAPIName: "tcbapi_slowcallfunction_v2",
			QBaseMeta: map[string]any{
				"filter_user_info": false,
				"sdk_version":      "wx-miniprogram-sdk/3.2.4 (1702450295000 platform/windows})",
				"session_id":       strconv.FormatInt(currentTime-2000, 10),
			},
			QBaseOptions: map[string]any{},
			QBaseReq:     string(qbaseReqPayload),
		},
		OperateDirectly: false,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode qbase_commapi data: %w", err)
	}
	return string(payloadJSON), nil
}

func randomDecimalString() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000_000_000_000))
	if err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return fmt.Sprintf("0.%018d", value.Int64()), nil
}

func operateWXDataCode(value *int) int {
	if value == nil {
		return 1
	}
	return *value
}

func operateWXDataMode(requestType int) string {
	if requestType == operateWXDataTypeGatewayServiceInfo {
		return native.OperateWXDataModeGatewayServiceInfo
	}
	return native.OperateWXDataModeDefault
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{
		"error": err.Error(),
	})
}

type oauthErrorDetail struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	WechatRet     *int64 `json:"wechat_ret,omitempty"`
	WechatMessage string `json:"wechat_message,omitempty"`
}

func writeOAuthServiceError(w http.ResponseWriter, err error) {
	var validationErr *service.OAuthValidationError
	if errors.As(err, &validationErr) {
		writeOAuthError(w, http.StatusBadRequest, validationErr)
		return
	}
	if errors.Is(err, service.ErrOAuthAccountNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": oauthErrorDetail{
			Code: "ACCOUNT_NOT_FOUND", Message: "unionid 对应账号不存在",
		}})
		return
	}
	var businessErr *service.OAuthBusinessError
	if errors.As(err, &businessErr) {
		ret := businessErr.Ret
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": oauthErrorDetail{
			Code: "OAUTH_BUSINESS_REJECTED", Message: "微信公众号授权失败",
			WechatRet: &ret, WechatMessage: businessErr.Message,
		}})
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{"error": oauthErrorDetail{
			Code: "OAUTH_TIMEOUT", Message: "微信公众号授权请求超时",
		}})
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{"error": oauthErrorDetail{
		Code: "OAUTH_UPSTREAM_ERROR", Message: err.Error(),
	}})
}

func writeOAuthError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"error": oauthErrorDetail{
		Code: "INVALID_REQUEST", Message: err.Error(),
	}})
}

func writeMethodNotAllowed(w http.ResponseWriter, method string) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
		"error": fmt.Sprintf("use %s", method),
	})
}

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if logger == nil {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/openapi.json" || r.URL.Path == "/favicon.ico" {
			next.ServeHTTP(w, r)
			return
		}

		startedAt := time.Now()
		requestID := requestIDFromHeader(r)
		w.Header().Set("X-Request-ID", requestID)

		recorder := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(recorder, r)

		attrs := []slog.Attr{
			slog.String("request_id", requestID),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("query", r.URL.RawQuery),
			slog.Int("status_code", recorder.statusCode),
			slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
			slog.Int("response_bytes", recorder.bytesWritten),
		}

		level := slog.LevelInfo
		if recorder.statusCode >= http.StatusBadRequest {
			level = slog.LevelWarn
		}
		logger.LogAttrs(r.Context(), level, "HTTP请求完成", attrs...)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
	wroteHeader  bool
}

func (w *loggingResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	if statusCode >= http.StatusContinue && statusCode < http.StatusOK && statusCode != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}
	w.wroteHeader = true
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *loggingResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytesWritten += n
	return n, err
}

func (w *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func requestIDFromHeader(r *http.Request) string {
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if requestID != "" {
		return requestID
	}
	return randomRequestID()
}

func randomRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return fmt.Sprintf("%x", buf)
}

func CORSHandler(allowedOrigins []string, next http.Handler) http.Handler {
	if len(allowedOrigins) == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowOrigin(origin, allowedOrigins) {
			if containsOrigin(allowedOrigins, "*") {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
		}

		if r.Method == http.MethodOptions &&
			r.Header.Get("Access-Control-Request-Method") != "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func allowOrigin(origin string, allowedOrigins []string) bool {
	if containsOrigin(allowedOrigins, "*") {
		return true
	}
	if origin == "" {
		return false
	}
	return containsOrigin(allowedOrigins, origin)
}

func containsOrigin(origins []string, target string) bool {
	for _, origin := range origins {
		if origin == target {
			return true
		}
	}
	return false
}

func shutdown(ctx context.Context, server *http.Server) error {
	return server.Shutdown(ctx)
}
