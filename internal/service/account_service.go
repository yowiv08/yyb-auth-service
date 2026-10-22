package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
	"yyb-auth-service/internal/store"
)

type AccountService struct {
	store      *store.AccountStore
	operations operationLocker
}

var ErrAccountNotFound = errors.New("account not found")

type DeleteAccountResult struct {
	UnionID              string
	DetachedScanSessions int64
}

type ScannedOAuthSession struct {
	GUID              string
	State             string
	WXCode            string
	OpenID            string
	AccessToken       string
	RefreshToken      string
	CookieExpiresAt   string
	LoginType         string
	UnionID           string
	LoginBuffer       string
	LoginBufferParsed map[string]any
}

func NewAccountService(
	store *store.AccountStore,
	operations operationLocker,
) *AccountService {
	return &AccountService{
		store:      store,
		operations: operations,
	}
}

func (s *AccountService) List(ctx context.Context) ([]model.Account, error) {
	return s.store.List(ctx)
}

func (s *AccountService) ByID(ctx context.Context, id int64) (model.Account, error) {
	return s.store.ByID(ctx, id)
}

func (s *AccountService) ByUnionID(ctx context.Context, unionID string) (model.Account, error) {
	return s.store.ByUnionID(ctx, unionID)
}

func (s *AccountService) Delete(ctx context.Context, unionID string) (DeleteAccountResult, error) {
	unionID = strings.TrimSpace(unionID)
	if unionID == "" {
		return DeleteAccountResult{}, fmt.Errorf("unionid required")
	}
	unlock, err := s.operations.LockOperation(ctx, unionID)
	if err != nil {
		return DeleteAccountResult{}, fmt.Errorf("lock account operation: %w", err)
	}
	defer unlock()

	result, err := s.store.Delete(ctx, unionID)
	if errors.Is(err, store.ErrAccountNotFound) {
		return DeleteAccountResult{}, fmt.Errorf("%w: %s", ErrAccountNotFound, unionID)
	}
	if err != nil {
		return DeleteAccountResult{}, err
	}
	return DeleteAccountResult{
		UnionID:              result.UnionID,
		DetachedScanSessions: result.DetachedScanSessions,
	}, nil
}

func (s *AccountService) UpsertScannedSession(
	ctx context.Context,
	scanned ScannedOAuthSession,
) (model.Account, error) {
	if scanned.UnionID == "" {
		return model.Account{}, fmt.Errorf("scanned session missing unionid")
	}
	if scanned.OpenID == "" {
		return model.Account{}, fmt.Errorf("scanned session missing openid")
	}
	if scanned.AccessToken == "" {
		return model.Account{}, fmt.Errorf("scanned session missing access token")
	}
	if scanned.RefreshToken == "" {
		return model.Account{}, fmt.Errorf("scanned session missing refresh token")
	}
	if scanned.GUID == "" {
		return model.Account{}, fmt.Errorf("scanned session missing guid")
	}
	unlock, err := s.operations.LockOperation(ctx, scanned.UnionID)
	if err != nil {
		return model.Account{}, fmt.Errorf("lock account operation: %w", err)
	}
	defer unlock()

	existing, hasExisting, err := s.lookupExistingAccount(ctx, scanned.UnionID)
	if err != nil {
		return model.Account{}, err
	}

	now := time.Now().UTC()
	protocolDevice, err := buildProtocolDevice(scanned.GUID, existing, now)
	if err != nil {
		return model.Account{}, err
	}

	protocolTDI, err := buildProtocolTDI(
		existing,
		scanned.OpenID,
		now,
	)
	if err != nil {
		return model.Account{}, err
	}

	loginType := firstNonEmpty(scanned.LoginType, "WX")
	saved := session.SavedSession{
		SavedAt: now.Format(time.RFC3339Nano),
		GUID:    scanned.GUID,
		WXCode:  scanned.WXCode,
		State:   scanned.State,
		TokenInfo: session.TokenInfo{
			OpenID:          scanned.OpenID,
			AccessToken:     scanned.AccessToken,
			RefreshToken:    scanned.RefreshToken,
			LoginType:       loginType,
			CookieExpiresAt: scanned.CookieExpiresAt,
			RefreshedAt:     now.Format(time.RFC3339Nano),
		},
		LoginBufferInfo: session.LoginBufferInfo{
			GUID:         scanned.GUID,
			OpenID:       scanned.OpenID,
			AccessToken:  scanned.AccessToken,
			RefreshToken: scanned.RefreshToken,
			LoginType:    loginType,
			LoginBuffer:  scanned.LoginBuffer,
			RefreshedAt:  now.Format(time.RFC3339Nano),
			Parsed:       scanned.LoginBufferParsed,
		},
		ProtocolDevice: protocolDevice,
		UnionID:        scanned.UnionID,
		ProtocolTDI:    protocolTDI,
	}

	protocolPayload, err := json.Marshal(protocolTDI)
	if err != nil {
		return model.Account{}, fmt.Errorf("encode protocol tdi: %w", err)
	}
	savedPayload, err := saved.Marshal()
	if err != nil {
		return model.Account{}, err
	}

	account := model.Account{
		UnionID:            scanned.UnionID,
		OpenID:             scanned.OpenID,
		GUID:               scanned.GUID,
		LoginType:          loginType,
		AccessToken:        scanned.AccessToken,
		RefreshToken:       scanned.RefreshToken,
		WXCode:             scanned.WXCode,
		State:              scanned.State,
		SavedSessionJSON:   string(savedPayload),
		RawProtocolTDIJSON: string(protocolPayload),
		DeviceIDB64:        protocolDevice.DeviceIDB64,
		AppDeviceID:        protocolDevice.AppDeviceID,
		Username:           stringValue(protocolTDI, "username", defaultUsername(scanned.OpenID)),
		UIN:                stringValue(protocolTDI, "uin", existing.UIN),
		AutoAuthKeyB64:     stringValue(protocolTDI, "autoauthKeyB64", existing.AutoAuthKeyB64),
		AutoAuthEncKeyB64:  stringValue(protocolTDI, "autoauthEncKeyB64", existing.AutoAuthEncKeyB64),
	}
	if hasExisting {
		account.CreatedAt = existing.CreatedAt
	}

	return s.store.Upsert(ctx, account)
}

func (s *AccountService) lookupExistingAccount(
	ctx context.Context,
	unionID string,
) (model.Account, bool, error) {
	account, err := s.store.ByUnionID(ctx, unionID)
	if err == nil {
		return account, true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return model.Account{}, false, nil
	}
	return model.Account{}, false, fmt.Errorf("lookup existing account: %w", err)
}

func buildProtocolDevice(
	guid string,
	existing model.Account,
	now time.Time,
) (session.ProtocolDevice, error) {
	deviceIDB64 := existing.DeviceIDB64
	appDeviceID := existing.AppDeviceID
	if deviceIDB64 == "" || appDeviceID == "" {
		deviceIDRaw, err := generateDeviceID()
		if err != nil {
			return session.ProtocolDevice{}, err
		}
		deviceIDB64 = base64.StdEncoding.EncodeToString(deviceIDRaw)
		appDeviceID = hex.EncodeToString(deviceIDRaw)[:16]
	}

	return session.ProtocolDevice{
		AppDeviceID: appDeviceID,
		DeviceIDB64: deviceIDB64,
		BoundGUID:   guid,
		Source:      "protocol-generated",
		UpdatedAt:   now.Format(time.RFC3339Nano),
	}, nil
}

func buildProtocolTDI(
	existing model.Account,
	openID string,
	now time.Time,
) (map[string]any, error) {
	protocolTDI := map[string]any{}
	if existing.RawProtocolTDIJSON != "" {
		if err := json.Unmarshal([]byte(existing.RawProtocolTDIJSON), &protocolTDI); err != nil {
			return nil, fmt.Errorf("decode existing protocol tdi: %w", err)
		}
	}
	if protocolTDI == nil {
		protocolTDI = map[string]any{}
	}

	protocolTDI["username"] = defaultUsername(openID)
	protocolTDI["updatedAt"] = now.Format(time.RFC3339Nano)

	if existing.UIN != "" {
		protocolTDI["uin"] = existing.UIN
	}

	if existing.AutoAuthKeyB64 != "" {
		protocolTDI["autoauthKeyB64"] = existing.AutoAuthKeyB64
	}
	if existing.AutoAuthEncKeyB64 != "" {
		protocolTDI["autoauthEncKeyB64"] = existing.AutoAuthEncKeyB64
		protocolTDI["sessionKeyB64"] = existing.AutoAuthEncKeyB64
	}

	return protocolTDI, nil
}

func generateDeviceID() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate device id: %w", err)
	}
	return buf, nil
}

func defaultUsername(openID string) string {
	return openID + "@im.ilinkapp_060000b7b93f6c"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func stringValue(values map[string]any, key string, fallback string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return fallback
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return fallback
	}
	return text
}
