package httpapi

import (
	"errors"
	"net/http"
	"time"

	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/service"
)

type renewCKResponse struct {
	OK           bool                `json:"ok"`
	CKUpdated    bool                `json:"ck_updated"`
	UnionID      string              `json:"unionid"`
	OpenID       string              `json:"openid,omitempty"`
	AppID        string              `json:"appid"`
	GUID         string              `json:"guid,omitempty"`
	LoginType    string              `json:"login_type,omitempty"`
	AccessToken  string              `json:"access_token,omitempty"`
	RefreshToken string              `json:"refresh_token,omitempty"`
	CKExpiresAt  string              `json:"ck_expires_at,omitempty"`
	Scope        string              `json:"scope,omitempty"`
	UserInfoOK   bool                `json:"userinfo_ok"`
	Error        *renewCKErrorDetail `json:"error,omitempty"`
	Duration     string              `json:"duration"`
}

type renewCKErrorDetail struct {
	Code      string `json:"code"`
	Stage     string `json:"stage"`
	Message   string `json:"message"`
	WechatRet *int64 `json:"wechat_ret,omitempty"`
}

func (s *Server) handleRenewCK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	startedAt := time.Now()
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		UnionID string `json:"unionid"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeRenewCKResponse(w, service.RenewCKResult{}, &service.RenewCKError{
			Code: "INVALID_REQUEST", Stage: "request", Message: "请求必须是仅包含 unionid 的 JSON 对象",
		}, time.Since(startedAt))
		return
	}
	result, err := s.renewCKService.Renew(r.Context(), body.UnionID)
	writeRenewCKResponse(w, result, err, time.Since(startedAt))
}

func writeRenewCKResponse(w http.ResponseWriter, result service.RenewCKResult, err error, elapsed time.Duration) {
	response := renewCKResponse{
		OK: result.OK, CKUpdated: result.CKUpdated, UnionID: result.Account.UnionID,
		AppID: native.QRConnectAppID, UserInfoOK: result.UserInfoOK, Duration: formatDurationHMS(elapsed),
	}
	if err == nil {
		response.OpenID, response.GUID = result.Account.OpenID, result.Account.GUID
		response.LoginType = result.Account.LoginType
		response.AccessToken, response.RefreshToken = result.Account.AccessToken, result.Account.RefreshToken
		response.CKExpiresAt, response.Scope = result.Account.CKExpiresAt, result.Scope
		writeJSON(w, http.StatusOK, response)
		return
	}
	response.OK = false
	renewalErr := &service.RenewCKError{Code: "CK_RENEW_UPSTREAM_ERROR", Stage: "renew", Message: "换新 CK 失败"}
	var typedErr *service.RenewCKError
	if errors.As(err, &typedErr) {
		renewalErr = typedErr
	}
	response.Error = &renewCKErrorDetail{Code: renewalErr.Code, Stage: renewalErr.Stage, Message: renewalErr.Message, WechatRet: renewalErr.WechatRet}
	status := http.StatusBadGateway
	switch renewalErr.Code {
	case "INVALID_REQUEST":
		status = http.StatusBadRequest
	case "ACCOUNT_NOT_FOUND":
		status = http.StatusNotFound
	case "OLD_SESSION_INVALID", "ACCOUNT_MISMATCH":
		status = http.StatusConflict
	case "QRCONNECT_REJECTED":
		status = http.StatusUnprocessableEntity
	case "CK_RENEW_TIMEOUT":
		status = http.StatusGatewayTimeout
	case "CK_SAVE_FAILED":
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, response)
}
