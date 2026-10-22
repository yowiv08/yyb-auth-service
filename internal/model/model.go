package model

import "time"

type Account struct {
	ID                 int64     `json:"-"`
	UnionID            string    `json:"unionid"`
	OpenID             string    `json:"openid"`
	GUID               string    `json:"guid"`
	LoginType          string    `json:"login_type"`
	AccessToken        string    `json:"access_token"`
	RefreshToken       string    `json:"refresh_token"`
	CKExpiresAt        string    `json:"ck_expires_at,omitempty"`
	WXCode             string    `json:"wx_code"`
	State              string    `json:"state"`
	SavedSessionJSON   string    `json:"-"`
	RawProtocolTDIJSON string    `json:"-"`
	DeviceIDB64        string    `json:"device_id_b64"`
	AppDeviceID        string    `json:"app_device_id"`
	Username           string    `json:"username"`
	UIN                string    `json:"uin"`
	AutoAuthKeyB64     string    `json:"autoauth_key_b64"`
	AutoAuthEncKeyB64  string    `json:"autoauth_enc_key_b64"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type CodeResult struct {
	UnionID    string    `json:"unionid"`
	AppID      string    `json:"appid"`
	Type       int       `json:"type"`
	Status     string    `json:"status"`
	Code       string    `json:"code"`
	ErrorText  string    `json:"error"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

type ScanSession struct {
	ID             int64     `json:"id"`
	Status         string    `json:"status"`
	GUID           string    `json:"guid"`
	State          string    `json:"state"`
	UUID           string    `json:"uuid"`
	QRURL          string    `json:"qr_url"`
	ExpiresAt      time.Time `json:"expires_at"`
	LastErrCode    string    `json:"last_errcode"`
	WXCode         string    `json:"wx_code"`
	OpenID         string    `json:"openid"`
	UnionID        string    `json:"unionid"`
	AccountID      *int64    `json:"-"`
	AccountUnionID string    `json:"account_unionid,omitempty"`
	CKExpiresAt    string    `json:"ck_expires_at,omitempty"`
	ErrorText      string    `json:"error"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
