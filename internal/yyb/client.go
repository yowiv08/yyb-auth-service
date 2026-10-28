package yyb

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	yybHost                = "yybadaccess.3g.qq.com"
	yybAppID               = "wxd44977328b36e647"
	userAgent              = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0 CefView/1.0 (Windows; en-us) YYBAppClient/5.10.6300.6090 Safari/537.36"
	qrRedirectURI          = "https://yybadaccess.3g.qq.com/pc_yyb/pcyyb_oauth?login_type=WX"
	wechatUserInfoEndpoint = "https://api.weixin.qq.com/sns/userinfo"
	accessKeyYYB           = "df683a7f1c814b4f84e752c6ed95c057"
	accessKeyAuth          = "wgrdg373hy26ww2"
	maxResponseBody        = 16 << 20
)

var (
	uuidRegex    = regexp.MustCompile(`var\s+uuid\s*=\s*["']([^"']+)["']`)
	qrImageRegex = regexp.MustCompile(`/connect/qrcode/([A-Za-z0-9_-]{8,64})`)
	gValueRegex  = regexp.MustCompile(`\bG\s*=\s*["']([^"']+)["']`)
	codeRegex    = regexp.MustCompile(`wx_code\s*=\s*['"]([^'"]*)['"]`)
	errCodeRegex = regexp.MustCompile(`wx_errcode\s*=\s*(\d+)`)
)

type Client struct {
	httpClient *http.Client
}

type HTTPStatusError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf(
		"upstream http status=%s body=%q",
		e.Status,
		e.Body,
	)
}

func IsHTTPStatus(err error, statusCode int) bool {
	var statusErr *HTTPStatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == statusCode
}

type Credentials struct {
	GUID            string
	OpenID          string
	AccessToken     string
	RefreshToken    string
	LoginType       string
	UnionID         string
	CookieExpiresAt string
}

type ScanInit struct {
	GUID  string
	State string
	UUID  string
	QRURL string
}

type ScanPollResult struct {
	ErrCode string
	WXCode  string
}

type OAuthResult struct {
	OpenID          string
	AccessToken     string
	RefreshToken    string
	CookieExpiresAt string
	Cookies         map[string]string
}

type UserInfo struct {
	OpenID     string   `json:"openid"`
	Nickname   string   `json:"nickname"`
	Sex        int      `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	HeadImgURL string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	UnionID    string   `json:"unionid"`
	ErrCode    int      `json:"errcode"`
	ErrMsg     string   `json:"errmsg"`
	RawJSON    string   `json:"-"`
}

type LoginBuffer struct {
	Raw        string
	AuthCode   string
	IlinkAppID string
	MPAppID    string
}

type FreshLoginBuffer struct {
	Credentials Credentials
	LoginBuffer LoginBuffer
	FetchedAt   time.Time
}

type LoginCodeResult struct {
	Code          string
	Ret           int
	Msg           string
	RawResultJSON string
	Credentials   Credentials
}

type signedPostOptions struct {
	BusinessID string
	AccessKey  string
	GUID       string
	Cookie     string
	Login      *Credentials
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(
				_ *http.Request,
				_ []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *Client) StartScan(ctx context.Context) (ScanInit, error) {
	guid, err := randomHex(16)
	if err != nil {
		return ScanInit{}, err
	}
	state, err := randomHex(16)
	if err != nil {
		return ScanInit{}, err
	}

	requestURL, err := url.Parse("https://open.weixin.qq.com/connect/qrconnect")
	if err != nil {
		return ScanInit{}, fmt.Errorf("build qrconnect url: %w", err)
	}
	query := requestURL.Query()
	query.Set("appid", yybAppID)
	query.Set("fast_login", "1")
	query.Set("redirect_uri", qrRedirectURI)
	query.Set("response_type", "code")
	query.Set("scope", "snsapi_login,snsapi_runtime_pcsdk")
	query.Set("self_redirect", "true")
	query.Set("state", guid)
	requestURL.RawQuery = query.Encode()

	cookie := strings.Join([]string{
		"yybClient-id=" + guid,
		"guid=" + guid,
		"login_method=fast_login",
		"scope=",
	}, "; ")
	headers := map[string]string{
		"User-Agent":      userAgent,
		"Accept":          "text/html,application/xhtml+xml",
		"Accept-Language": "en-US,en;q=0.9",
		"Referer":         "https://pc.yyb.qq.com/",
		"Cookie":          cookie,
	}

	body, _, err := c.do(ctx, http.MethodGet, requestURL.String(), nil, headers)
	if err != nil {
		return ScanInit{}, err
	}

	matches := uuidRegex.FindStringSubmatch(string(body))
	if len(matches) != 2 {
		matches = qrImageRegex.FindStringSubmatch(string(body))
	}
	if len(matches) != 2 {
		matches = gValueRegex.FindStringSubmatch(string(body))
	}
	if len(matches) != 2 {
		return ScanInit{}, fmt.Errorf("uuid not found in qrconnect html")
	}

	uuid := matches[1]
	return ScanInit{
		GUID:  guid,
		State: state,
		UUID:  uuid,
		QRURL: "https://open.weixin.qq.com/connect/qrcode/" + uuid,
	}, nil
}

func (c *Client) PollScan(ctx context.Context, uuid string, lastErrCode string) (ScanPollResult, error) {
	requestURL, err := url.Parse("https://lp.open.weixin.qq.com/connect/l/qrconnect")
	if err != nil {
		return ScanPollResult{}, fmt.Errorf("build poll url: %w", err)
	}
	query := requestURL.Query()
	query.Set("uuid", uuid)
	query.Set("_", strconvFormatInt(time.Now().UnixMilli()))
	if lastErrCode != "" {
		query.Set("last", lastErrCode)
	}
	requestURL.RawQuery = query.Encode()

	headers := map[string]string{
		"User-Agent": userAgent,
		"Accept":     "*/*",
		"Referer":    "https://open.weixin.qq.com/",
		"Cookie":     "scope=",
	}

	body, _, err := c.do(ctx, http.MethodGet, requestURL.String(), nil, headers)
	if err != nil {
		return ScanPollResult{}, err
	}
	text := string(body)

	result := ScanPollResult{}
	if matches := errCodeRegex.FindStringSubmatch(text); len(matches) == 2 {
		result.ErrCode = matches[1]
	}
	if matches := codeRegex.FindStringSubmatch(text); len(matches) == 2 {
		result.WXCode = matches[1]
	}
	return result, nil
}

func (c *Client) ExchangeOAuth(ctx context.Context, guid string, wxCode string) (OAuthResult, error) {
	requestURL, err := url.Parse("https://yybadaccess.3g.qq.com/pc_yyb/pcyyb_oauth")
	if err != nil {
		return OAuthResult{}, fmt.Errorf("build oauth url: %w", err)
	}
	query := requestURL.Query()
	query.Set("login_type", "WX")
	query.Set("code", wxCode)
	query.Set("state", guid)
	requestURL.RawQuery = query.Encode()

	headers := map[string]string{
		"User-Agent": userAgent,
		"Accept":     "text/html,application/json",
		"Origin":     "https://open.weixin.qq.com",
		"Referer":    "https://open.weixin.qq.com/",
		"Cookie":     "scope=snsapi_login%2Csnsapi_runtime_pcsdk",
	}

	_, response, err := c.do(ctx, http.MethodGet, requestURL.String(), nil, headers)
	if err != nil {
		return OAuthResult{}, err
	}

	cookies := map[string]string{}
	for _, cookie := range response.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	if cookies["openid"] == "" || cookies["accesstoken"] == "" {
		return OAuthResult{}, fmt.Errorf("oauth cookies missing openid/accesstoken")
	}

	return OAuthResult{
		OpenID:          cookies["openid"],
		AccessToken:     cookies["accesstoken"],
		RefreshToken:    cookies["refreshtoken"],
		CookieExpiresAt: cookieExpiresAt(response),
		Cookies:         cookies,
	}, nil
}

func cookieExpiresAt(response *http.Response) string {
	if response == nil {
		return ""
	}

	headers := response.Header.Values("Set-Cookie")
	if expiresAt := setCookieExpiresAt(headers, "refreshtoken"); expiresAt != "" {
		return expiresAt
	}
	if expiresAt := firstSetCookieExpiresAt(headers); expiresAt != "" {
		return expiresAt
	}
	for _, cookie := range response.Cookies() {
		if !cookie.Expires.IsZero() {
			return cookie.Expires.UTC().Format(http.TimeFormat)
		}
	}
	return ""
}

func setCookieExpiresAt(headers []string, cookieName string) string {
	for _, header := range headers {
		name, _, ok := strings.Cut(strings.TrimSpace(header), "=")
		if !ok || !strings.EqualFold(name, cookieName) {
			continue
		}
		if expiresAt := expiresAttr(header); expiresAt != "" {
			return expiresAt
		}
	}
	return ""
}

func firstSetCookieExpiresAt(headers []string) string {
	for _, header := range headers {
		if expiresAt := expiresAttr(header); expiresAt != "" {
			return expiresAt
		}
	}
	return ""
}

func expiresAttr(setCookie string) string {
	for _, part := range strings.Split(setCookie, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(key, "Expires") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (c *Client) RefreshToken(
	ctx context.Context,
	creds Credentials,
) (Credentials, error) {
	body := map[string]any{
		"userInfo": map[string]any{
			"openId":       creds.OpenID,
			"refreshToken": creds.RefreshToken,
			"accessToken":  creds.AccessToken,
			"loginType":    firstNonEmpty(creds.LoginType, "WX"),
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return Credentials{}, fmt.Errorf("encode refresh token request: %w", err)
	}

	responseBody, response, err := c.signedPost(
		ctx,
		"/pc_yyb_auth/pcyyb_refresh_token_auth",
		payload,
		signedPostOptions{
			BusinessID: "pc_yyb_auth",
			AccessKey:  accessKeyAuth,
			GUID:       creds.GUID,
		},
	)
	if err != nil {
		return Credentials{}, err
	}

	decoded, err := decodeCredentialResponse(
		"refresh token", responseBody, response,
		creds.AccessToken, creds.RefreshToken, creds.OpenID, creds.GUID, creds.UnionID,
	)
	if err != nil {
		return Credentials{}, err
	}
	return refreshedCredentials(creds, decoded, response)
}

func (c *Client) GetUserInfo(
	ctx context.Context,
	accessToken string,
	openID string,
	lang string,
) (UserInfo, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return UserInfo{}, fmt.Errorf("access_token 必填")
	}
	openID = strings.TrimSpace(openID)
	if openID == "" {
		return UserInfo{}, fmt.Errorf("openid 必填")
	}

	requestURL, err := url.Parse(wechatUserInfoEndpoint)
	if err != nil {
		return UserInfo{}, fmt.Errorf("构造微信 userinfo url: %w", err)
	}
	query := requestURL.Query()
	query.Set("access_token", accessToken)
	query.Set("openid", openID)
	query.Set("lang", lang)
	requestURL.RawQuery = query.Encode()

	responseBody, response, err := c.do(
		ctx,
		http.MethodGet,
		requestURL.String(),
		nil,
		map[string]string{
			"Accept":     "application/json",
			"User-Agent": userAgent,
		},
	)
	if err != nil {
		return UserInfo{}, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return UserInfo{}, &HTTPStatusError{
			StatusCode: response.StatusCode,
			Status:     response.Status,
			Body:       bodyPreview(responseBody),
		}
	}

	var userInfo UserInfo
	if err := decodeJSONResponse("微信 userinfo 响应", responseBody, response, &userInfo); err != nil {
		return UserInfo{}, err
	}
	userInfo.RawJSON = string(bytes.TrimSpace(responseBody))
	if userInfo.Privilege == nil {
		userInfo.Privilege = []string{}
	}
	return userInfo, nil
}

func (c *Client) GetUnionID(
	ctx context.Context,
	openID string,
	accessToken string,
) (string, error) {
	body := map[string]any{
		"extInfo": map[string]any{
			"listS": map[string]any{
				"openid":       map[string]any{"value": []string{openID}},
				"access_token": map[string]any{"value": []string{accessToken}},
			},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encode unionid request: %w", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://pc.yyb.qq.com",
		"Referer":      "https://pc.yyb.qq.com/",
		"User-Agent":   userAgent,
	}
	responseBody, response, err := c.do(
		ctx,
		http.MethodPost,
		"https://"+yybHost+"/pc_yyb/pcyyb_get_wx_unionid",
		payload,
		headers,
	)
	if err != nil {
		return "", err
	}

	var decoded map[string]any
	if err := decodeJSONResponse("unionid response", responseBody, response, &decoded); err != nil {
		return "", err
	}
	unionID := firstJSONValue(decoded, "ext_info", "list_s", "unionid")
	if unionID == "" {
		unionID = firstJSONValue(decoded, "extInfo", "listS", "unionid")
	}
	if unionID == "" {
		return "", fmt.Errorf("unionid missing in response")
	}

	return unionID, nil
}

func (c *Client) GetLoginBuffer(
	ctx context.Context,
	creds OAuthResult,
	guid string,
	unionID string,
) (LoginBuffer, error) {
	body := map[string]any{
		"extInfo": map[string]any{
			"listS": map[string]any{
				"unionid":      map[string]any{"value": []string{unionID}},
				"user_id":      map[string]any{"value": []string{guid}},
				"access_token": map[string]any{"value": []string{creds.AccessToken}},
			},
			"listI": map[string]any{
				"user_type": map[string]any{"value": []int{1}},
			},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return LoginBuffer{}, fmt.Errorf("encode login buffer request: %w", err)
	}

	responseBody, response, err := c.signedPost(
		ctx,
		"/pc_yyb_auth/pcyyb_get_wx_login_buffer_auth",
		payload,
		signedPostOptions{
			BusinessID: "pc_yyb_auth",
			AccessKey:  accessKeyAuth,
			GUID:       guid,
			Cookie:     "scope=snsapi_login%2Csnsapi_runtime_pcsdk",
		},
	)
	if err != nil {
		return LoginBuffer{}, err
	}

	decoded, err := decodeCredentialResponse(
		"login buffer", responseBody, response,
		creds.AccessToken, creds.RefreshToken, creds.OpenID, guid, unionID,
	)
	if err != nil {
		return LoginBuffer{}, err
	}

	raw := firstJSONValue(decoded, "ext_info", "list_s", "login_buffer")
	if raw == "" {
		raw = firstJSONValue(decoded, "extInfo", "listS", "loginBuffer")
	}
	if raw == "" {
		return LoginBuffer{}, fmt.Errorf("login_buffer missing in response")
	}

	authCode, ilinkAppID, mpAppID, err := parseLoginBuffer(raw)
	if err != nil {
		return LoginBuffer{}, err
	}

	return LoginBuffer{
		Raw:        raw,
		AuthCode:   authCode,
		IlinkAppID: ilinkAppID,
		MPAppID:    mpAppID,
	}, nil
}

func (c *Client) FetchAuthcodeOnce(
	ctx context.Context,
	creds Credentials,
) (FreshLoginBuffer, error) {
	refreshed, err := c.RefreshToken(ctx, creds)
	if err != nil {
		return FreshLoginBuffer{}, err
	}

	unionID := strings.TrimSpace(creds.UnionID)
	if unionID == "" {
		unionID, err = c.GetUnionID(ctx, refreshed.OpenID, refreshed.AccessToken)
		if err != nil {
			return FreshLoginBuffer{}, fmt.Errorf("get unionid: %w", err)
		}
	}
	if unionID == "" {
		return FreshLoginBuffer{}, fmt.Errorf("unionid is empty")
	}
	refreshed.UnionID = unionID

	loginBuffer, err := c.GetLoginBuffer(
		ctx,
		OAuthResult{
			OpenID:       refreshed.OpenID,
			AccessToken:  refreshed.AccessToken,
			RefreshToken: refreshed.RefreshToken,
		},
		refreshed.GUID,
		unionID,
	)
	if err != nil {
		return FreshLoginBuffer{}, fmt.Errorf("get login buffer: %w", err)
	}

	return FreshLoginBuffer{
		Credentials: refreshed,
		LoginBuffer: loginBuffer,
		FetchedAt:   time.Now().UTC(),
	}, nil
}

func (c *Client) GetLoginCode(
	ctx context.Context,
	creds Credentials,
	appID string,
) (LoginCodeResult, error) {
	refreshed, err := c.RefreshToken(ctx, creds)
	if err != nil {
		return LoginCodeResult{}, err
	}

	unionID := strings.TrimSpace(refreshed.UnionID)
	if unionID == "" {
		unionID, err = c.GetUnionID(ctx, refreshed.OpenID, refreshed.AccessToken)
		if err != nil {
			return LoginCodeResult{
				Credentials: refreshed,
			}, fmt.Errorf("get unionid: %w", err)
		}
	}
	if unionID == "" {
		return LoginCodeResult{
			Credentials: refreshed,
		}, fmt.Errorf("unionid is empty")
	}
	refreshed.UnionID = unionID

	body := map[string]any{
		"extInfo": map[string]any{
			"listS": map[string]any{
				"unionid":   map[string]any{"value": []string{unionID}},
				"wxa_appid": map[string]any{"value": []string{appID}},
				"user_id":   map[string]any{"value": []string{refreshed.GUID}},
			},
			"listI": map[string]any{
				"user_type": map[string]any{"value": []int{1}},
			},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return LoginCodeResult{
			Credentials: refreshed,
		}, fmt.Errorf("encode login code request: %w", err)
	}

	responseBody, response, err := c.signedPost(
		ctx,
		"/pc_yyb/pcyyb_get_wx_login_code",
		payload,
		signedPostOptions{
			BusinessID: "pc_yyb",
			AccessKey:  accessKeyYYB,
			GUID:       refreshed.GUID,
			Login:      &refreshed,
		},
	)
	if err != nil {
		return LoginCodeResult{
			Credentials: refreshed,
		}, err
	}

	var decoded map[string]any
	if err := decodeJSONResponse("login code response", responseBody, response, &decoded); err != nil {
		return LoginCodeResult{
			RawResultJSON: string(responseBody),
			Credentials:   refreshed,
		}, err
	}

	result := LoginCodeResult{
		Ret:           intJSONValue(decoded, "code"),
		Msg:           firstNonEmpty(firstJSONValue(decoded, "msg"), firstJSONValue(decoded, "ret_msg")),
		RawResultJSON: string(responseBody),
		Credentials:   refreshed,
	}
	if result.Ret != 0 {
		return result, fmt.Errorf("get login code failed ret=%d msg=%q", result.Ret, result.Msg)
	}

	result.Code = firstNonEmpty(
		firstJSONValue(decoded, "ext_info", "list_s", "login_code"),
		firstJSONValue(decoded, "extInfo", "listS", "loginCode"),
		firstJSONValue(decoded, "extInfo", "listS", "login_code"),
	)
	if result.Code == "" {
		return result, fmt.Errorf("login_code missing in response")
	}

	return result, nil
}

func (c *Client) GetLoginCodeFast(
	ctx context.Context,
	unionID string,
	appID string,
) (LoginCodeResult, error) {
	unionID = strings.TrimSpace(unionID)
	if unionID == "" {
		return LoginCodeResult{}, fmt.Errorf("unionid is empty")
	}

	body := map[string]any{
		"extInfo": map[string]any{
			"listS": map[string]any{
				"unionid":   map[string]any{"value": []string{unionID}},
				"wxa_appid": map[string]any{"value": []string{appID}},
				"user_id":   map[string]any{"value": []string{unionID}},
			},
			"listI": map[string]any{
				"user_type": map[string]any{"value": []int{0}},
			},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return LoginCodeResult{}, fmt.Errorf("encode login code request: %w", err)
	}

	responseBody, response, err := c.signedPost(
		ctx,
		"/pc_yyb/pcyyb_get_wx_login_code",
		payload,
		signedPostOptions{
			BusinessID: "pc_yyb",
			AccessKey:  accessKeyYYB,
		},
	)
	if err != nil {
		return LoginCodeResult{RawResultJSON: string(responseBody)}, err
	}

	var decoded map[string]any
	if err := decodeJSONResponse("login code response", responseBody, response, &decoded); err != nil {
		return LoginCodeResult{RawResultJSON: string(responseBody)}, err
	}

	result := LoginCodeResult{
		Ret:           intJSONValue(decoded, "code"),
		Msg:           firstNonEmpty(firstJSONValue(decoded, "msg"), firstJSONValue(decoded, "ret_msg")),
		RawResultJSON: string(responseBody),
	}
	if result.Ret != 0 {
		return result, fmt.Errorf("get login code failed ret=%d msg=%q", result.Ret, result.Msg)
	}

	result.Code = firstNonEmpty(
		firstJSONValue(decoded, "ext_info", "list_s", "login_code"),
		firstJSONValue(decoded, "extInfo", "listS", "loginCode"),
		firstJSONValue(decoded, "extInfo", "listS", "login_code"),
	)
	if result.Code == "" {
		return result, fmt.Errorf("login_code missing in response")
	}
	return result, nil
}

func (c *Client) do(
	ctx context.Context,
	method string,
	targetURL string,
	body []byte,
	headers map[string]string,
) ([]byte, *http.Response, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		method,
		targetURL,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("perform request: %w", err)
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read response body: %w", err)
	}
	if len(payload) > maxResponseBody {
		return nil, response, fmt.Errorf("upstream response body exceeds %d bytes", maxResponseBody)
	}
	return payload, response, nil
}

func (c *Client) signedPost(
	ctx context.Context,
	path string,
	payload []byte,
	opts signedPostOptions,
) ([]byte, *http.Response, error) {
	timestamp := strconvFormatInt(time.Now().UnixMilli())
	nonce := randomDigits(4)
	headers := map[string]string{
		"Content-Type":          "application/json",
		"Ual-Access-Businessid": opts.BusinessID,
		"Ual-Access-Timestamp":  timestamp,
		"Ual-Access-Nonce":      nonce,
		"Ual-Access-Signature":  sign(payload, timestamp, opts.AccessKey, nonce),
		"Ual-Access-Requestid":  randomDigits(4),
		"Origin":                "https://pc.yyb.qq.com",
		"Referer":               "https://pc.yyb.qq.com/",
		"User-Agent":            userAgent,
	}
	if strings.TrimSpace(opts.GUID) != "" {
		headers["Ual-Access-Guid"] = opts.GUID
	}
	if strings.TrimSpace(opts.Cookie) != "" {
		headers["Cookie"] = opts.Cookie
	}
	if opts.Login != nil {
		headers["Ual-Access-Login-Type"] = "1"
		headers["Ual-Access-Openid"] = opts.Login.OpenID
		headers["Ual-Access-Access-Token"] = opts.Login.AccessToken
	}

	return c.do(
		ctx,
		http.MethodPost,
		"https://"+yybHost+path,
		payload,
		headers,
	)
}

func decodeJSONResponse(
	label string,
	body []byte,
	response *http.Response,
	target any,
) error {
	if response != nil && (response.StatusCode < 200 || response.StatusCode >= 300) {
		return &HTTPStatusError{
			StatusCode: response.StatusCode,
			Status:     response.Status,
			Body:       bodyPreview(body),
		}
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return fmt.Errorf(
			"decode %s: empty response status=%s content_type=%q",
			label,
			responseStatus(response),
			responseContentType(response),
		)
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("decode %s: null response status=%s", label, responseStatus(response))
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf(
			"decode %s: status=%s body=%q: %w",
			label,
			responseStatus(response),
			bodyPreview(body),
			err,
		)
	}
	return nil
}

func responseStatus(response *http.Response) string {
	if response == nil {
		return "unknown"
	}
	return response.Status
}

func responseContentType(response *http.Response) string {
	if response == nil {
		return ""
	}
	return response.Header.Get("Content-Type")
}

func bodyPreview(body []byte) string {
	const maxBodyPreview = 512

	text := strings.Join(strings.Fields(string(body)), " ")
	if len(text) <= maxBodyPreview {
		return text
	}
	return text[:maxBodyPreview] + "..."
}

func randomHex(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func randomDigits(length int) string {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", length)
	}
	for index := range buf {
		buf[index] = '0' + (buf[index] % 10)
	}
	return string(buf)
}

func sign(body []byte, timestamp string, accessKey string, nonce string) string {
	sum := md5.Sum(append(append(append([]byte{}, body...), []byte(timestamp)...), []byte(accessKey+nonce)...))
	return hex.EncodeToString(sum[:])
}

func parseLoginBuffer(raw string) (string, string, string, error) {
	payload, err := url.QueryUnescape(raw)
	if err == nil && payload != raw {
		raw = payload
	}

	decoded, err := decodeBase64String(raw)
	if err != nil {
		return "", "", "", fmt.Errorf("decode login_buffer: %w", err)
	}

	fields := map[int]string{}
	for offset := 0; offset < len(decoded); {
		tag := int(decoded[offset])
		offset++
		field := tag >> 3
		wireType := tag & 0x7
		if wireType != 2 {
			break
		}
		length, next, err := readVarint(decoded, offset)
		if err != nil {
			return "", "", "", err
		}
		offset = next
		end := offset + length
		if end > len(decoded) {
			return "", "", "", fmt.Errorf("login_buffer field %d truncated", field)
		}
		fields[field] = string(decoded[offset:end])
		offset = end
	}

	return fields[1], fields[2], fields[3], nil
}

func decodeBase64String(raw string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
	}

	var firstErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(raw)
		if err == nil {
			return decoded, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	return nil, firstErr
}

func readVarint(buf []byte, offset int) (int, int, error) {
	value := 0
	shift := 0
	cursor := offset
	for cursor < len(buf) {
		current := int(buf[cursor])
		cursor++
		value |= (current & 0x7f) << shift
		if current < 0x80 {
			return value, cursor, nil
		}
		shift += 7
		if shift > 28 {
			return 0, 0, fmt.Errorf("varint too long")
		}
	}
	return 0, 0, fmt.Errorf("truncated varint")
}

func firstJSONValue(payload map[string]any, keys ...string) string {
	var current any = payload
	for _, key := range keys {
		next, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = next[key]
	}

	switch typed := current.(type) {
	case string:
		return typed
	case map[string]any:
		values, ok := typed["value"].([]any)
		if !ok || len(values) == 0 {
			return ""
		}
		value, ok := values[0].(string)
		if !ok {
			return ""
		}
		return value
	default:
		return ""
	}
}

func nestedString(payload map[string]any, keys ...string) string {
	var current any = payload
	for _, key := range keys {
		next, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = next[key]
	}

	text, ok := current.(string)
	if !ok {
		return ""
	}
	return text
}

func intJSONValue(payload map[string]any, key string) int {
	value, ok := payload[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	default:
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func strconvFormatInt(value int64) string {
	return fmt.Sprintf("%d", value)
}
