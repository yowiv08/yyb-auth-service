package httpapi

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/service"
)

type userResponse struct {
	UnionID           string `json:"unionid"`
	OpenID            string `json:"openid"`
	GUID              string `json:"guid"`
	LoginType         string `json:"login_type"`
	AccessToken       string `json:"access_token"`
	RefreshToken      string `json:"refresh_token"`
	CKExpiresAt       string `json:"ck_expires_at"`
	WXCode            string `json:"wx_code"`
	State             string `json:"state"`
	DeviceIDB64       string `json:"device_id_b64"`
	AppDeviceID       string `json:"app_device_id"`
	Username          string `json:"username"`
	UIN               string `json:"uin"`
	AutoAuthKeyB64    string `json:"autoauth_key_b64"`
	AutoAuthEncKeyB64 string `json:"autoauth_enc_key_b64"`
	Duration          string `json:"duration"`
}

type deleteUserResponse struct {
	OK                   bool   `json:"ok"`
	UnionID              string `json:"unionid"`
	Deleted              bool   `json:"deleted"`
	DetachedScanSessions int64  `json:"detached_scan_sessions"`
}

type codeResultResponse struct {
	UnionID  string `json:"unionid"`
	AppID    string `json:"appid"`
	Type     int    `json:"type"`
	Status   string `json:"status"`
	Code     string `json:"code"`
	Error    string `json:"error"`
	Duration string `json:"duration"`
}

type operateWXDataResponse struct {
	OK                 bool                              `json:"ok"`
	AppID              string                            `json:"appid"`
	OperateCode        int                               `json:"operate_code"`
	Duration           string                            `json:"duration"`
	Request            native.OperateWXDataRequestTrace  `json:"request"`
	Response           native.OperateWXDataResponseTrace `json:"response"`
	GatewayServiceInfo *gatewayServiceInfoResponse       `json:"gateway_service_info,omitempty"`
	Decoded            map[string]any                    `json:"decoded,omitempty"`
	DecodedRaw         string                            `json:"decoded_raw,omitempty"`
}

type gatewayServiceInfoResponse struct {
	OK       bool   `json:"ok"`
	Token    string `json:"token,omitempty"`
	Key      string `json:"key,omitempty"`
	RID      any    `json:"rid"`
	QBaseRID string `json:"qbase_rid"`
	KX       string `json:"kx,omitempty"`
	ClientKX string `json:"client_kx,omitempty"`
	ServerKX string `json:"server_kx,omitempty"`
	IAT      any    `json:"iat,omitempty"`
	Exp      any    `json:"exp,omitempty"`
	Source   string `json:"source"`
	Error    string `json:"error,omitempty"`
}

type gatewayServiceInfoCandidate struct {
	Token string
	Key   string
	RID   any
	KX    string
	IAT   any
	Exp   any
}

type userInfoResponse struct {
	OK         bool     `json:"ok"`
	UnionID    string   `json:"unionid"`
	OpenID     string   `json:"openid"`
	Nickname   string   `json:"nickname"`
	HeadImgURL string   `json:"headimgurl"`
	Sex        int      `json:"sex"`
	Country    string   `json:"country"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Privilege  []string `json:"privilege"`
	ErrCode    int      `json:"errcode,omitempty"`
	ErrMsg     string   `json:"errmsg,omitempty"`
	Duration   string   `json:"duration"`
}

type oauthAuthorizeResponse struct {
	Status           string                   `json:"status"`
	UnionID          string                   `json:"unionid"`
	AppID            string                   `json:"appid"`
	Scope            string                   `json:"scope"`
	State            string                   `json:"state"`
	AuthorizationURL string                   `json:"authorization_url"`
	Code             string                   `json:"code"`
	IsRecentHasAuth  bool                     `json:"is_recent_has_auth"`
	IsSilentAuth     bool                     `json:"is_silent_auth"`
	ScopeList        []native.OAuthScopeInfo  `json:"scope_list"`
	AvatarList       []native.OAuthAvatarInfo `json:"avatar_list"`
	Duration         string                   `json:"duration"`
}

type oauthConfirmResponse struct {
	Status      string `json:"status"`
	UnionID     string `json:"unionid"`
	AppID       string `json:"appid"`
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
	Duration    string `json:"duration"`
}

type phoneResponse struct {
	OK            bool   `json:"ok"`
	Mobile        string `json:"mobile"`
	ShowMobile    string `json:"show_mobile"`
	EncryptedData string `json:"encryptedData"`
	IV            string `json:"iv"`
	Code          string `json:"code"`
	Data          string `json:"data,omitempty"`
	CloudID       string `json:"cloud_id,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	Error         string `json:"error,omitempty"`
	Duration      string `json:"duration"`
}

type scanSessionResponse struct {
	ID             int64  `json:"id"`
	Status         string `json:"status"`
	GUID           string `json:"guid"`
	State          string `json:"state"`
	UUID           string `json:"uuid"`
	QRURL          string `json:"qr_url"`
	ScanExpiresIn  string `json:"scan_expires_in"`
	LastErrCode    string `json:"last_errcode"`
	WXCode         string `json:"wx_code"`
	OpenID         string `json:"openid"`
	UnionID        string `json:"unionid"`
	AccountUnionID string `json:"account_unionid,omitempty"`
	CKExpiresAt    string `json:"ck_expires_at"`
	Error          string `json:"error"`
	Duration       string `json:"duration"`
}

func makeUserResponses(accounts []model.Account) []userResponse {
	users := make([]userResponse, 0, len(accounts))
	for _, account := range accounts {
		users = append(users, makeUserResponse(account))
	}
	return users
}

func makeUserResponse(account model.Account) userResponse {
	return userResponse{
		UnionID:           account.UnionID,
		OpenID:            account.OpenID,
		GUID:              account.GUID,
		LoginType:         account.LoginType,
		AccessToken:       account.AccessToken,
		RefreshToken:      account.RefreshToken,
		CKExpiresAt:       account.CKExpiresAt,
		WXCode:            account.WXCode,
		State:             account.State,
		DeviceIDB64:       account.DeviceIDB64,
		AppDeviceID:       account.AppDeviceID,
		Username:          account.Username,
		UIN:               account.UIN,
		AutoAuthKeyB64:    account.AutoAuthKeyB64,
		AutoAuthEncKeyB64: account.AutoAuthEncKeyB64,
		Duration:          formatDurationHMS(account.UpdatedAt.Sub(account.CreatedAt)),
	}
}

func makeDeleteUserResponse(result service.DeleteAccountResult) deleteUserResponse {
	return deleteUserResponse{
		OK:                   true,
		UnionID:              result.UnionID,
		Deleted:              true,
		DetachedScanSessions: result.DetachedScanSessions,
	}
}

func makeCodeResultResponse(result model.CodeResult) codeResultResponse {
	return codeResultResponse{
		UnionID:  result.UnionID,
		AppID:    result.AppID,
		Type:     result.Type,
		Status:   result.Status,
		Code:     result.Code,
		Error:    result.ErrorText,
		Duration: formatDurationHMS(result.FinishedAt.Sub(result.StartedAt)),
	}
}

func makeOperateWXDataResponse(
	result native.OperateWXDataResult,
	duration time.Duration,
	gatewayRequest *gatewayServiceInfoRequest,
) operateWXDataResponse {
	var gatewayServiceInfo *gatewayServiceInfoResponse
	if gatewayRequest != nil {
		value := makeGatewayServiceInfoResponse(result, gatewayRequest)
		gatewayServiceInfo = &value
	}

	return operateWXDataResponse{
		OK:                 result.OK,
		AppID:              result.AppID,
		OperateCode:        result.OperateCode,
		Duration:           formatDurationHMS(duration),
		Request:            result.Request,
		Response:           result.Response,
		GatewayServiceInfo: gatewayServiceInfo,
		Decoded:            result.Decoded,
		DecodedRaw:         result.DecodedRaw,
	}
}

func makeGatewayServiceInfoResponse(
	result native.OperateWXDataResult,
	request *gatewayServiceInfoRequest,
) gatewayServiceInfoResponse {
	response := gatewayServiceInfoResponse{
		OK:       false,
		RID:      request.RID,
		QBaseRID: request.RID,
		Source:   request.Source,
	}

	candidate, ok := findGatewayServiceInfoCandidate(result.Decoded, 0)
	if !ok {
		candidate, ok = findGatewayServiceInfoCandidate(result.DecodedRaw, 0)
	}
	if !ok {
		response.Error = "response missing Gateway token with key or server kx"
		return response
	}

	response.Token = candidate.Token
	response.Key = candidate.Key
	if scalarStringValue(candidate.RID) != "" {
		response.RID = candidate.RID
	}
	response.KX = candidate.KX
	response.ClientKX = request.ClientKX
	response.IAT = candidate.IAT
	response.Exp = candidate.Exp
	if response.Key == "" {
		if candidate.KX == "" {
			response.Error = "response missing Gateway key and server kx"
			return response
		}
		if request.ClientPrivateKey == "" {
			response.Error = "cannot derive Gateway key without client private key"
			return response
		}
		if strings.EqualFold(candidate.KX, request.ClientKX) {
			response.Error = "server kx equals client kx"
			return response
		}
		key, err := deriveGatewayServiceInfoKey(request.ClientPrivateKey, candidate.KX)
		if err != nil {
			response.Error = fmt.Sprintf("derive Gateway key: %v", err)
			return response
		}
		response.Key = key
		response.ServerKX = candidate.KX
	}
	response.OK = true
	return response
}

func findGatewayServiceInfoCandidate(value any, depth int) (gatewayServiceInfoCandidate, bool) {
	const maxDepth = 20
	const maxJSONTextLength = 200000

	if depth > maxDepth {
		return gatewayServiceInfoCandidate{}, false
	}

	switch typed := value.(type) {
	case map[string]any:
		isRequestObject := stringValue(typed["qbase_api_name"]) == gatewayServiceInfoAPIName ||
			typed["qbase_req"] != nil
		if !isRequestObject {
			token := stringValue(typed["token"])
			key := stringValue(typed["key"])
			kx := stringValue(typed["kx"])
			if token != "" && (key != "" || kx != "") {
				return gatewayServiceInfoCandidate{
					Token: token,
					Key:   key,
					RID:   typed["rid"],
					KX:    kx,
					IAT:   typed["iat"],
					Exp:   typed["exp"],
				}, true
			}
		}
		for _, child := range typed {
			if candidate, ok := findGatewayServiceInfoCandidate(child, depth+1); ok {
				return candidate, true
			}
		}
	case []any:
		for _, child := range typed {
			if candidate, ok := findGatewayServiceInfoCandidate(child, depth+1); ok {
				return candidate, true
			}
		}
	case string:
		text := strings.TrimSpace(typed)
		if len(text) == 0 || len(text) > maxJSONTextLength {
			return gatewayServiceInfoCandidate{}, false
		}
		if !strings.HasPrefix(text, "{") && !strings.HasPrefix(text, "[") {
			return gatewayServiceInfoCandidate{}, false
		}

		var decoded any
		if err := json.Unmarshal([]byte(text), &decoded); err != nil {
			return gatewayServiceInfoCandidate{}, false
		}
		return findGatewayServiceInfoCandidate(decoded, depth+1)
	}

	return gatewayServiceInfoCandidate{}, false
}

func deriveGatewayServiceInfoKey(privateHex string, peerHex string) (string, error) {
	privateBytes, err := hex.DecodeString(strings.TrimSpace(privateHex))
	if err != nil {
		return "", err
	}
	peerBytes, err := hex.DecodeString(strings.TrimSpace(peerHex))
	if err != nil {
		return "", err
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return "", err
	}
	peerKey, err := ecdh.X25519().NewPublicKey(peerBytes)
	if err != nil {
		return "", err
	}
	secret, err := privateKey.ECDH(peerKey)
	if err != nil {
		return "", err
	}
	key, err := hkdf.Key(sha256.New, secret, nil, "", 16)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func stringValue(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func scalarStringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return fmt.Sprintf("%.0f", typed)
	case float32:
		return fmt.Sprintf("%.0f", typed)
	case int:
		return fmt.Sprintf("%d", typed)
	case int32:
		return fmt.Sprintf("%d", typed)
	case int64:
		return fmt.Sprintf("%d", typed)
	case uint:
		return fmt.Sprintf("%d", typed)
	case uint32:
		return fmt.Sprintf("%d", typed)
	case uint64:
		return fmt.Sprintf("%d", typed)
	default:
		return ""
	}
}

func makeUserInfoResponse(
	result service.UserInfoResult,
	duration time.Duration,
) userInfoResponse {
	privilege := append([]string{}, result.Privilege...)
	if privilege == nil {
		privilege = []string{}
	}

	return userInfoResponse{
		OK:         result.OK,
		UnionID:    result.UnionID,
		OpenID:     result.OpenID,
		Nickname:   result.Nickname,
		HeadImgURL: result.HeadImgURL,
		Sex:        result.Sex,
		Country:    result.Country,
		Province:   result.Province,
		City:       result.City,
		Privilege:  privilege,
		ErrCode:    result.ErrCode,
		ErrMsg:     result.ErrMsg,
		Duration:   formatDurationHMS(duration),
	}
}

func makeOAuthAuthorizeResponse(
	result service.OAuthAuthorizeResult,
	duration time.Duration,
) oauthAuthorizeResponse {
	return oauthAuthorizeResponse{
		Status: result.Status, UnionID: result.UnionID, AppID: result.AppID,
		Scope: result.Scope, State: result.State, AuthorizationURL: result.AuthorizationURL,
		Code: result.Code, IsRecentHasAuth: result.IsRecentHasAuth,
		IsSilentAuth: result.IsSilentAuth, ScopeList: result.ScopeList,
		AvatarList: result.AvatarList, Duration: formatDurationHMS(duration),
	}
}

func makeOAuthConfirmResponse(
	result service.OAuthConfirmResult,
	duration time.Duration,
) oauthConfirmResponse {
	return oauthConfirmResponse{
		Status: result.Status, UnionID: result.UnionID, AppID: result.AppID,
		Code: result.Code, State: result.State, RedirectURI: result.RedirectURI,
		Duration: formatDurationHMS(duration),
	}
}

func makePhoneResponse(
	result native.PhoneResult,
	duration time.Duration,
) phoneResponse {
	return phoneResponse{
		OK:            result.OK,
		Mobile:        result.Mobile,
		ShowMobile:    result.ShowMobile,
		EncryptedData: result.EncryptedData,
		IV:            result.IV,
		Code:          result.Code,
		Data:          result.Data,
		CloudID:       result.CloudID,
		RequestID:     result.RequestID,
		Error:         result.ErrorText,
		Duration:      formatDurationHMS(duration),
	}
}

func makeScanSessionResponse(scan model.ScanSession, now time.Time) scanSessionResponse {
	return scanSessionResponse{
		ID:             scan.ID,
		Status:         scan.Status,
		GUID:           scan.GUID,
		State:          scan.State,
		UUID:           scan.UUID,
		QRURL:          scan.QRURL,
		ScanExpiresIn:  formatRemainingDuration(scanExpiresIn(scan, now)),
		LastErrCode:    scan.LastErrCode,
		WXCode:         scan.WXCode,
		OpenID:         scan.OpenID,
		UnionID:        scan.UnionID,
		AccountUnionID: scan.AccountUnionID,
		CKExpiresAt:    scan.CKExpiresAt,
		Error:          scan.ErrorText,
		Duration:       formatDurationHMS(scan.UpdatedAt.Sub(scan.CreatedAt)),
	}
}

func scanExpiresIn(scan model.ScanSession, now time.Time) time.Duration {
	switch scan.Status {
	case "canceled", "completed", "expired", "failed":
		return 0
	default:
		return scan.ExpiresAt.Sub(now)
	}
}

func formatRemainingDuration(duration time.Duration) string {
	if duration <= 0 {
		return "0S"
	}
	return formatDurationHMS(duration)
}

func formatDurationHMS(duration time.Duration) string {
	seconds := int64(duration / time.Second)
	if seconds < 1 {
		seconds = 1
	}

	var result strings.Builder
	if hours := seconds / 3600; hours > 0 {
		fmt.Fprintf(&result, "%dH", hours)
	}
	if minutes := seconds % 3600 / 60; minutes > 0 {
		fmt.Fprintf(&result, "%dM", minutes)
	}
	if seconds := seconds % 60; seconds > 0 {
		fmt.Fprintf(&result, "%dS", seconds)
	}
	return result.String()
}
