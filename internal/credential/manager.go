package credential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
	"yyb-auth-service/internal/yyb"
)

const credentialPersistenceTimeout = 5 * time.Second

type AccountRepository interface {
	ByUnionID(ctx context.Context, unionID string) (model.Account, error)
	Update(ctx context.Context, account model.Account) (model.Account, error)
}

type AuthClient interface {
	RefreshToken(
		ctx context.Context,
		credentials yyb.Credentials,
	) (yyb.Credentials, error)
	GetLoginBuffer(
		ctx context.Context,
		credentials yyb.OAuthResult,
		guid string,
		unionID string,
	) (yyb.LoginBuffer, error)
}

type Manager struct {
	accounts AccountRepository
	client   AuthClient
	now      func() time.Time

	locksMu sync.Mutex
	locks   map[string]*lockEntry

	operationLocksMu sync.Mutex
	operationLocks   map[string]*lockEntry
}

type lockEntry struct {
	semaphore  chan struct{}
	references int
}

func NewManager(accounts AccountRepository, client AuthClient) *Manager {
	return &Manager{
		accounts:       accounts,
		client:         client,
		now:            time.Now,
		locks:          map[string]*lockEntry{},
		operationLocks: map[string]*lockEntry{},
	}
}

func (m *Manager) LockOperation(
	ctx context.Context,
	unionID string,
) (func(), error) {
	normalized, err := normalizeUnionID(unionID)
	if err != nil {
		return nil, err
	}
	return lockKeyed(
		ctx,
		normalized,
		&m.operationLocksMu,
		m.operationLocks,
	)
}

func (m *Manager) Account(
	ctx context.Context,
	unionID string,
) (model.Account, error) {
	normalized, err := normalizeUnionID(unionID)
	if err != nil {
		return model.Account{}, err
	}
	return m.accounts.ByUnionID(ctx, normalized)
}

func (m *Manager) FreshLoginBuffer(
	ctx context.Context,
	unionID string,
) (model.Account, yyb.FreshLoginBuffer, error) {
	normalized, err := normalizeUnionID(unionID)
	if err != nil {
		return model.Account{}, yyb.FreshLoginBuffer{}, err
	}

	unlock, err := m.lock(ctx, normalized)
	if err != nil {
		return model.Account{}, yyb.FreshLoginBuffer{}, err
	}
	defer unlock()

	account, err := m.accounts.ByUnionID(ctx, normalized)
	if err != nil {
		return model.Account{}, yyb.FreshLoginBuffer{}, err
	}

	saved, err := decodeSavedSession(account)
	if err != nil {
		return model.Account{}, yyb.FreshLoginBuffer{}, err
	}

	credentials := credentialsFromAccount(account)
	loginBuffer, err := m.getLoginBuffer(
		ctx,
		credentials,
		account.UnionID,
	)
	if yyb.IsCredentialExpired(err) {
		loginErr := err
		account, saved, err = m.refreshLocked(ctx, account, saved)
		if err != nil {
			return model.Account{}, yyb.FreshLoginBuffer{}, errors.Join(
				fmt.Errorf("get login buffer: %w", loginErr),
				err,
			)
		}
		credentials = credentialsFromAccount(account)
		loginBuffer, err = m.getLoginBuffer(
			ctx,
			credentials,
			account.UnionID,
		)
	}
	if err != nil {
		return account, yyb.FreshLoginBuffer{}, fmt.Errorf("get login buffer: %w", err)
	}

	fetchedAt := m.now().UTC()
	applyLoginBuffer(&saved, credentials, loginBuffer, fetchedAt)
	account, err = m.persistSavedLocked(ctx, account, saved)
	if err != nil {
		return model.Account{}, yyb.FreshLoginBuffer{}, err
	}

	return account, yyb.FreshLoginBuffer{
		Credentials: credentials,
		LoginBuffer: loginBuffer,
		FetchedAt:   fetchedAt,
	}, nil
}

func (m *Manager) RecoverExpired(
	ctx context.Context,
	unionID string,
	rejectedAccessToken string,
) (model.Account, error) {
	normalized, err := normalizeUnionID(unionID)
	if err != nil {
		return model.Account{}, err
	}

	unlock, err := m.lock(ctx, normalized)
	if err != nil {
		return model.Account{}, err
	}
	defer unlock()

	account, err := m.accounts.ByUnionID(ctx, normalized)
	if err != nil {
		return model.Account{}, err
	}
	if strings.TrimSpace(account.AccessToken) != strings.TrimSpace(rejectedAccessToken) {
		return account, nil
	}

	saved, err := decodeSavedSession(account)
	if err != nil {
		return model.Account{}, err
	}
	account, _, err = m.refreshLocked(ctx, account, saved)
	return account, err
}

func (m *Manager) MergeSession(
	ctx context.Context,
	unionID string,
	saved session.SavedSession,
) (model.Account, error) {
	normalized, err := normalizeUnionID(unionID)
	if err != nil {
		return model.Account{}, err
	}

	unlock, err := m.lock(ctx, normalized)
	if err != nil {
		return model.Account{}, err
	}
	defer unlock()

	account, err := m.accounts.ByUnionID(ctx, normalized)
	if err != nil {
		return model.Account{}, err
	}

	currentSaved, err := decodeSavedSession(account)
	if err != nil {
		return model.Account{}, err
	}
	// Only credential refresh and scanning replace web credentials. A native
	// operation may have newer protocol state without having refreshed a token.
	saved.TokenInfo = currentSaved.TokenInfo
	applyCredentials(&saved, credentialsFromAccount(account), "")
	if isAfter(
		currentSaved.LoginBufferInfo.RefreshedAt,
		saved.LoginBufferInfo.RefreshedAt,
	) {
		saved.LoginBufferInfo = currentSaved.LoginBufferInfo
	}
	applyLoginCredentials(&saved, credentialsFromAccount(account))
	if isAfter(currentSaved.SavedAt, saved.SavedAt) {
		saved.SavedAt = currentSaved.SavedAt
	}
	return m.persistSavedLocked(ctx, account, saved)
}

func (m *Manager) refreshLocked(
	ctx context.Context,
	account model.Account,
	saved session.SavedSession,
) (model.Account, session.SavedSession, error) {
	credentials, err := m.client.RefreshToken(ctx, credentialsFromAccount(account))
	if err != nil {
		return model.Account{}, session.SavedSession{}, fmt.Errorf("refresh credentials: %w", err)
	}
	if strings.TrimSpace(credentials.AccessToken) == "" {
		return model.Account{}, session.SavedSession{}, fmt.Errorf("refresh credentials: access token is empty")
	}

	refreshedAt := m.now().UTC().Format(time.RFC3339Nano)
	applyCredentials(&saved, credentials, refreshedAt)
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialPersistenceTimeout)
	defer cancel()
	account, err = m.persistSavedLocked(persistCtx, account, saved)
	if err != nil {
		return model.Account{}, session.SavedSession{}, err
	}
	return account, saved, nil
}

func (m *Manager) getLoginBuffer(
	ctx context.Context,
	credentials yyb.Credentials,
	unionID string,
) (yyb.LoginBuffer, error) {
	oauth := yyb.OAuthResult{
		OpenID:       credentials.OpenID,
		AccessToken:  credentials.AccessToken,
		RefreshToken: credentials.RefreshToken,
	}

	return m.client.GetLoginBuffer(ctx, oauth, credentials.GUID, unionID)
}

func (m *Manager) persistSavedLocked(
	ctx context.Context,
	account model.Account,
	saved session.SavedSession,
) (model.Account, error) {
	if saved.ProtocolTDI == nil {
		saved.ProtocolTDI = map[string]any{}
	}

	protocolPayload, err := json.Marshal(saved.ProtocolTDI)
	if err != nil {
		return model.Account{}, fmt.Errorf("encode updated protocol tdi: %w", err)
	}
	savedPayload, err := saved.Marshal()
	if err != nil {
		return model.Account{}, err
	}

	account.OpenID = saved.TokenInfo.OpenID
	account.AccessToken = saved.TokenInfo.AccessToken
	account.RefreshToken = saved.TokenInfo.RefreshToken
	account.LoginType = saved.TokenInfo.LoginType
	account.WXCode = saved.WXCode
	account.State = saved.State
	account.SavedSessionJSON = string(savedPayload)
	account.RawProtocolTDIJSON = string(protocolPayload)
	account.DeviceIDB64 = saved.ProtocolDevice.DeviceIDB64
	account.AppDeviceID = saved.ProtocolDevice.AppDeviceID
	account.Username = mapString(saved.ProtocolTDI, "username", account.Username)
	account.UIN = mapString(saved.ProtocolTDI, "uin", account.UIN)
	account.AutoAuthKeyB64 = mapString(
		saved.ProtocolTDI,
		"autoauthKeyB64",
		account.AutoAuthKeyB64,
	)
	account.AutoAuthEncKeyB64 = mapString(
		saved.ProtocolTDI,
		"autoauthEncKeyB64",
		account.AutoAuthEncKeyB64,
	)
	account.UpdatedAt = m.now().UTC()

	updated, err := m.accounts.Update(ctx, account)
	if err != nil {
		return model.Account{}, fmt.Errorf("persist credentials: %w", err)
	}
	return updated, nil
}

func (m *Manager) lock(
	ctx context.Context,
	key string,
) (func(), error) {
	return lockKeyed(ctx, key, &m.locksMu, m.locks)
}

func normalizeUnionID(unionID string) (string, error) {
	normalized := strings.TrimSpace(unionID)
	if normalized == "" {
		return "", fmt.Errorf("unionid is required")
	}
	return normalized, nil
}

func decodeSavedSession(account model.Account) (session.SavedSession, error) {
	var saved session.SavedSession
	if err := json.Unmarshal([]byte(account.SavedSessionJSON), &saved); err != nil {
		return session.SavedSession{}, fmt.Errorf("decode account saved session: %w", err)
	}
	if saved.ProtocolTDI == nil {
		saved.ProtocolTDI = map[string]any{}
	}
	return saved, nil
}

func credentialsFromAccount(account model.Account) yyb.Credentials {
	return yyb.Credentials{
		GUID:            account.GUID,
		OpenID:          account.OpenID,
		AccessToken:     account.AccessToken,
		RefreshToken:    account.RefreshToken,
		LoginType:       firstNonEmpty(account.LoginType, "WX"),
		UnionID:         account.UnionID,
		CookieExpiresAt: account.CKExpiresAt,
	}
}

func applyCredentials(
	saved *session.SavedSession,
	credentials yyb.Credentials,
	refreshedAt string,
) {
	saved.GUID = credentials.GUID
	saved.UnionID = firstNonEmpty(credentials.UnionID, saved.UnionID)
	saved.TokenInfo.OpenID = credentials.OpenID
	saved.TokenInfo.AccessToken = credentials.AccessToken
	saved.TokenInfo.RefreshToken = credentials.RefreshToken
	saved.TokenInfo.LoginType = firstNonEmpty(credentials.LoginType, "WX")
	if strings.TrimSpace(credentials.CookieExpiresAt) != "" {
		saved.TokenInfo.CookieExpiresAt = credentials.CookieExpiresAt
	}
	if strings.TrimSpace(refreshedAt) != "" {
		saved.TokenInfo.RefreshedAt = refreshedAt
		saved.SavedAt = refreshedAt
	}

	saved.LoginBufferInfo.GUID = credentials.GUID
	saved.LoginBufferInfo.OpenID = credentials.OpenID
	saved.LoginBufferInfo.AccessToken = credentials.AccessToken
	saved.LoginBufferInfo.RefreshToken = credentials.RefreshToken
	saved.LoginBufferInfo.LoginType = firstNonEmpty(credentials.LoginType, "WX")
}

func applyLoginBuffer(
	saved *session.SavedSession,
	credentials yyb.Credentials,
	loginBuffer yyb.LoginBuffer,
	fetchedAt time.Time,
) {
	refreshedAt := fetchedAt.UTC().Format(time.RFC3339Nano)
	applyCredentials(saved, credentials, "")
	saved.SavedAt = refreshedAt
	saved.LoginBufferInfo.LoginBuffer = loginBuffer.Raw
	saved.LoginBufferInfo.RefreshedAt = refreshedAt
	saved.LoginBufferInfo.Parsed = map[string]any{
		"authCode":   loginBuffer.AuthCode,
		"ilinkAppId": loginBuffer.IlinkAppID,
		"mpAppId":    loginBuffer.MPAppID,
	}
}

func applyLoginCredentials(
	saved *session.SavedSession,
	credentials yyb.Credentials,
) {
	saved.LoginBufferInfo.GUID = credentials.GUID
	saved.LoginBufferInfo.OpenID = credentials.OpenID
	saved.LoginBufferInfo.AccessToken = credentials.AccessToken
	saved.LoginBufferInfo.RefreshToken = credentials.RefreshToken
	saved.LoginBufferInfo.LoginType = firstNonEmpty(credentials.LoginType, "WX")
}

func lockKeyed(
	ctx context.Context,
	key string,
	mutex *sync.Mutex,
	entries map[string]*lockEntry,
) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mutex.Lock()
	entry := entries[key]
	if entry == nil {
		entry = &lockEntry{semaphore: make(chan struct{}, 1)}
		entries[key] = entry
	}
	entry.references++
	mutex.Unlock()

	releaseReference := func() {
		mutex.Lock()
		defer mutex.Unlock()
		entry.references--
		if entry.references == 0 && entries[key] == entry {
			delete(entries, key)
		}
	}

	select {
	case entry.semaphore <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-entry.semaphore
			releaseReference()
			return nil, err
		}
		return func() {
			<-entry.semaphore
			releaseReference()
		}, nil
	case <-ctx.Done():
		releaseReference()
		return nil, ctx.Err()
	}
}

func isAfter(candidate string, reference string) bool {
	candidateTime, candidateErr := time.Parse(
		time.RFC3339Nano,
		strings.TrimSpace(candidate),
	)
	referenceTime, referenceErr := time.Parse(
		time.RFC3339Nano,
		strings.TrimSpace(reference),
	)
	if candidateErr != nil {
		return false
	}
	if referenceErr != nil {
		return true
	}
	return candidateTime.After(referenceTime)
}

func mapString(values map[string]any, key string, fallback string) string {
	value, ok := values[key]
	if !ok {
		return fallback
	}
	typed, ok := value.(string)
	if !ok || strings.TrimSpace(typed) == "" {
		return fallback
	}
	return typed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
