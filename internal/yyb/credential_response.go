package yyb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// BusinessError preserves an upstream rejection without retaining its response body.
type BusinessError struct {
	Operation string
	Code      int
	Message   string
}

func (e *BusinessError) Error() string {
	return fmt.Sprintf("%s failed code=%d msg=%s", e.Operation, e.Code, e.Message)
}

// IsCredentialExpired identifies explicit authentication failures. Parameter and
// permission errors alone do not establish that an access token has expired.
func IsCredentialExpired(err error) bool {
	if IsHTTPStatus(err, http.StatusUnauthorized) || IsHTTPStatus(err, http.StatusForbidden) {
		return true
	}
	var businessErr *BusinessError
	if !errors.As(err, &businessErr) {
		return false
	}
	switch businessErr.Code {
	case 40001, 40014, 42001:
		return true
	}
	return strings.TrimSpace(businessErr.Message) == "access_token and refresh_token exception"
}

func decodeCredentialResponse(
	operation string,
	body []byte,
	response *http.Response,
	secrets ...string,
) (map[string]any, error) {
	if response != nil && (response.StatusCode < 200 || response.StatusCode >= 300) {
		return nil, &HTTPStatusError{StatusCode: response.StatusCode, Status: response.Status}
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", operation, err)
	}
	code, err := credentialResponseCode(raw["code"])
	if err != nil {
		return nil, fmt.Errorf("%s response: %w", operation, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", operation, err)
	}
	if code != 0 {
		message := firstNonEmpty(
			firstJSONValue(decoded, "msg"),
			firstJSONValue(decoded, "message"),
			firstJSONValue(decoded, "errMsg"),
		)
		for _, secret := range secrets {
			if secret = strings.TrimSpace(secret); secret != "" {
				message = strings.ReplaceAll(message, secret, "[redacted]")
			}
		}
		return nil, &BusinessError{Operation: operation, Code: code, Message: message}
	}
	return decoded, nil
}

func credentialResponseCode(raw json.RawMessage) (int, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0, fmt.Errorf("code is missing")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return 0, fmt.Errorf("code must be an integer")
	}
	var text string
	switch typed := value.(type) {
	case json.Number:
		text = string(typed)
	case string:
		text = typed
	default:
		return 0, fmt.Errorf("code must be an integer")
	}
	code, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("code must be an integer")
	}
	return code, nil
}

func refreshedCredentials(
	previous Credentials,
	decoded map[string]any,
	response *http.Response,
) (Credentials, error) {
	cookies := map[string]string{}
	if response != nil {
		for _, cookie := range response.Cookies() {
			cookies[strings.ToLower(cookie.Name)] = strings.TrimSpace(cookie.Value)
		}
	}
	openID := credentialUserInfoValue(decoded, "openid", "openId")
	loginType := credentialUserInfoValue(decoded, "loginType", "login_type")
	expectedOpenID := strings.TrimSpace(previous.OpenID)
	expectedLoginType := strings.TrimSpace(firstNonEmpty(previous.LoginType, "WX"))
	returnedOpenIDs := append(credentialUserInfoValues(decoded, "openid", "openId"), cookies["openid"])
	for _, returnedOpenID := range returnedOpenIDs {
		if returnedOpenID == "" {
			continue
		}
		if expectedOpenID == "" {
			expectedOpenID = returnedOpenID
		}
		if returnedOpenID != expectedOpenID {
			return Credentials{}, fmt.Errorf("refresh token response changed account openid")
		}
	}
	returnedLoginTypes := append(credentialUserInfoValues(decoded, "loginType", "login_type"), cookies["logintype"])
	for _, returnedLoginType := range returnedLoginTypes {
		if returnedLoginType != "" && returnedLoginType != expectedLoginType {
			return Credentials{}, fmt.Errorf("refresh token response changed account login type")
		}
	}
	accessToken := firstNonEmpty(
		credentialUserInfoValue(decoded, "accessToken", "access_token", "token"),
		cookies["accesstoken"],
	)
	if accessToken == "" {
		return Credentials{}, fmt.Errorf("refresh token response: access token is missing")
	}
	updated := previous
	updated.OpenID = firstNonEmpty(openID, cookies["openid"], previous.OpenID)
	updated.LoginType = firstNonEmpty(loginType, cookies["logintype"], expectedLoginType)
	updated.AccessToken = accessToken
	updated.RefreshToken = firstNonEmpty(
		credentialUserInfoValue(decoded, "refreshToken", "refresh_token"),
		cookies["refreshtoken"],
		previous.RefreshToken,
	)
	if expiresAt := cookieExpiresAt(response); expiresAt != "" {
		updated.CookieExpiresAt = expiresAt
	}
	return updated, nil
}

func credentialUserInfoValue(decoded map[string]any, keys ...string) string {
	values := credentialUserInfoValues(decoded, keys...)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func credentialUserInfoValues(decoded map[string]any, keys ...string) []string {
	var values []string
	for _, object := range []string{"userInfo", "user_info"} {
		for _, key := range keys {
			if value := strings.TrimSpace(nestedString(decoded, object, key)); value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}
