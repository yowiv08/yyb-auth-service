package session

import (
	"encoding/json"
	"fmt"
	"os"
)

type SavedSession struct {
	SavedAt         string          `json:"savedAt"`
	GUID            string          `json:"guid"`
	WXCode          string          `json:"wxCode"`
	State           string          `json:"state"`
	TokenInfo       TokenInfo       `json:"tokenInfo"`
	LoginBufferInfo LoginBufferInfo `json:"loginBufferInfo"`
	ProtocolDevice  ProtocolDevice  `json:"protocolDevice"`
	UnionID         string          `json:"unionid"`
	ProtocolTDI     map[string]any  `json:"protocolTdi"`
}

type TokenInfo struct {
	OpenID          string `json:"openid"`
	AccessToken     string `json:"accessToken"`
	RefreshToken    string `json:"refreshToken"`
	LoginType       string `json:"loginType"`
	CookieExpiresAt string `json:"cookieExpiresAt,omitempty"`
	RefreshedAt     string `json:"refreshedAt"`
}

type LoginBufferInfo struct {
	GUID         string         `json:"guid"`
	OpenID       string         `json:"openid"`
	AccessToken  string         `json:"accessToken"`
	RefreshToken string         `json:"refreshToken"`
	LoginType    string         `json:"loginType"`
	LoginBuffer  string         `json:"loginBuffer"`
	RefreshedAt  string         `json:"refreshedAt"`
	Parsed       map[string]any `json:"parsed"`
}

type ProtocolDevice struct {
	AppDeviceID string `json:"appDeviceId"`
	DeviceIDB64 string `json:"deviceIdB64"`
	BoundGUID   string `json:"boundGuid"`
	Source      string `json:"source"`
	UpdatedAt   string `json:"updatedAt"`
}

func LoadFile(path string) (SavedSession, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return SavedSession{}, fmt.Errorf("read saved session: %w", err)
	}

	var saved SavedSession
	if err := json.Unmarshal(payload, &saved); err != nil {
		return SavedSession{}, fmt.Errorf("decode saved session: %w", err)
	}

	return saved, nil
}

func (s SavedSession) Marshal() ([]byte, error) {
	payload, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode saved session: %w", err)
	}
	return payload, nil
}
