package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
)

type AccountStore struct {
	db *sql.DB
}

var ErrAccountNotFound = errors.New("account not found")

type DeleteAccountResult struct {
	UnionID              string
	DetachedScanSessions int64
}

func NewAccountStore(db *sql.DB) *AccountStore {
	return &AccountStore{db: db}
}

func (s *AccountStore) Upsert(ctx context.Context, account model.Account) (model.Account, error) {
	now := time.Now().UTC()
	if account.CreatedAt.IsZero() {
		account.CreatedAt = now
	}
	account.UpdatedAt = now

	query := `
	insert into accounts (
		unionid,
		openid,
		guid,
		login_type,
		access_token,
		refresh_token,
		wx_code,
		state,
		saved_session_json,
		raw_protocol_tdi_json,
		device_id_b64,
		app_device_id,
		username,
		uin,
		autoauth_key_b64,
		autoauth_enc_key_b64,
		created_at,
		updated_at
	) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	on conflict(unionid) do update set
		openid = excluded.openid,
		guid = excluded.guid,
		login_type = excluded.login_type,
		access_token = excluded.access_token,
		refresh_token = excluded.refresh_token,
		wx_code = excluded.wx_code,
		state = excluded.state,
		saved_session_json = excluded.saved_session_json,
		raw_protocol_tdi_json = excluded.raw_protocol_tdi_json,
		device_id_b64 = excluded.device_id_b64,
		app_device_id = excluded.app_device_id,
		username = excluded.username,
		uin = excluded.uin,
		autoauth_key_b64 = excluded.autoauth_key_b64,
		autoauth_enc_key_b64 = excluded.autoauth_enc_key_b64,
		updated_at = excluded.updated_at
	`

	if _, err := s.db.ExecContext(
		ctx,
		query,
		account.UnionID,
		account.OpenID,
		account.GUID,
		account.LoginType,
		account.AccessToken,
		account.RefreshToken,
		account.WXCode,
		account.State,
		account.SavedSessionJSON,
		account.RawProtocolTDIJSON,
		account.DeviceIDB64,
		account.AppDeviceID,
		account.Username,
		account.UIN,
		account.AutoAuthKeyB64,
		account.AutoAuthEncKeyB64,
		account.CreatedAt.Format(time.RFC3339Nano),
		account.UpdatedAt.Format(time.RFC3339Nano),
	); err != nil {
		return model.Account{}, fmt.Errorf("upsert account: %w", err)
	}

	return s.ByUnionID(ctx, account.UnionID)
}

func (s *AccountStore) Update(ctx context.Context, account model.Account) (model.Account, error) {
	account.UpdatedAt = time.Now().UTC()
	result, err := s.db.ExecContext(
		ctx,
		`update accounts set
			openid = ?,
			guid = ?,
			login_type = ?,
			access_token = ?,
			refresh_token = ?,
			wx_code = ?,
			state = ?,
			saved_session_json = ?,
			raw_protocol_tdi_json = ?,
			device_id_b64 = ?,
			app_device_id = ?,
			username = ?,
			uin = ?,
			autoauth_key_b64 = ?,
			autoauth_enc_key_b64 = ?,
			updated_at = ?
		where unionid = ?`,
		account.OpenID,
		account.GUID,
		account.LoginType,
		account.AccessToken,
		account.RefreshToken,
		account.WXCode,
		account.State,
		account.SavedSessionJSON,
		account.RawProtocolTDIJSON,
		account.DeviceIDB64,
		account.AppDeviceID,
		account.Username,
		account.UIN,
		account.AutoAuthKeyB64,
		account.AutoAuthEncKeyB64,
		account.UpdatedAt.Format(time.RFC3339Nano),
		account.UnionID,
	)
	if err != nil {
		return model.Account{}, fmt.Errorf("update account: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return model.Account{}, fmt.Errorf("read updated account rows: %w", err)
	}
	if rowsAffected == 0 {
		return model.Account{}, ErrAccountNotFound
	}
	return s.ByUnionID(ctx, account.UnionID)
}

func (s *AccountStore) ByID(ctx context.Context, id int64) (model.Account, error) {
	return s.queryOne(ctx, accountSelectSQL(`where id = ?`), id)
}

func (s *AccountStore) ByUnionID(ctx context.Context, unionID string) (model.Account, error) {
	return s.queryOne(ctx, accountSelectSQL(`where unionid = ?`), unionID)
}

func (s *AccountStore) Delete(ctx context.Context, unionID string) (DeleteAccountResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeleteAccountResult{}, fmt.Errorf("begin delete account transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var accountID int64
	var storedUnionID string
	err = tx.QueryRowContext(
		ctx,
		`select id, unionid from accounts where unionid = ?`,
		unionID,
	).Scan(&accountID, &storedUnionID)
	if errors.Is(err, sql.ErrNoRows) {
		return DeleteAccountResult{}, fmt.Errorf("%w: %s", ErrAccountNotFound, unionID)
	}
	if err != nil {
		return DeleteAccountResult{}, fmt.Errorf("find account for deletion: %w", err)
	}

	detachResult, err := tx.ExecContext(
		ctx,
		`update scan_sessions set account_id = null where account_id = ?`,
		accountID,
	)
	if err != nil {
		return DeleteAccountResult{}, fmt.Errorf("detach account scan sessions: %w", err)
	}
	detachedScanSessions, err := detachResult.RowsAffected()
	if err != nil {
		return DeleteAccountResult{}, fmt.Errorf("count detached scan sessions: %w", err)
	}

	result, err := tx.ExecContext(ctx, `delete from accounts where id = ?`, accountID)
	if err != nil {
		return DeleteAccountResult{}, fmt.Errorf("delete account: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return DeleteAccountResult{}, fmt.Errorf("count deleted accounts: %w", err)
	}
	if deleted != 1 {
		return DeleteAccountResult{}, fmt.Errorf(
			"delete account affected %d rows, expected 1",
			deleted,
		)
	}

	if err = tx.Commit(); err != nil {
		return DeleteAccountResult{}, fmt.Errorf("commit delete account transaction: %w", err)
	}

	return DeleteAccountResult{
		UnionID:              storedUnionID,
		DetachedScanSessions: detachedScanSessions,
	}, nil
}

func (s *AccountStore) List(ctx context.Context) ([]model.Account, error) {
	rows, err := s.db.QueryContext(ctx, accountSelectSQL(`order by id asc`))
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	accounts := make([]model.Account, 0)
	for rows.Next() {
		account, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list accounts rows: %w", err)
	}

	return accounts, nil
}

func (s *AccountStore) queryOne(ctx context.Context, query string, args ...any) (model.Account, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
	account, err := scanAccount(row)
	if err != nil {
		return model.Account{}, err
	}
	return account, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func accountSelectSQL(suffix string) string {
	return `
	select
		id,
		unionid,
		openid,
		guid,
		login_type,
		access_token,
		refresh_token,
		wx_code,
		state,
		saved_session_json,
		raw_protocol_tdi_json,
		device_id_b64,
		app_device_id,
		username,
		uin,
		autoauth_key_b64,
		autoauth_enc_key_b64,
		created_at,
		updated_at
	from accounts ` + suffix
}

func scanAccount(row scanner) (model.Account, error) {
	var (
		account      model.Account
		createdAtRaw string
		updatedAtRaw string
	)

	err := row.Scan(
		&account.ID,
		&account.UnionID,
		&account.OpenID,
		&account.GUID,
		&account.LoginType,
		&account.AccessToken,
		&account.RefreshToken,
		&account.WXCode,
		&account.State,
		&account.SavedSessionJSON,
		&account.RawProtocolTDIJSON,
		&account.DeviceIDB64,
		&account.AppDeviceID,
		&account.Username,
		&account.UIN,
		&account.AutoAuthKeyB64,
		&account.AutoAuthEncKeyB64,
		&createdAtRaw,
		&updatedAtRaw,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Account{}, fmt.Errorf("account not found: %w", err)
		}
		return model.Account{}, fmt.Errorf("scan account: %w", err)
	}

	account.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAtRaw)
	if err != nil {
		return model.Account{}, fmt.Errorf("parse account created_at: %w", err)
	}
	account.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAtRaw)
	if err != nil {
		return model.Account{}, fmt.Errorf("parse account updated_at: %w", err)
	}
	attachAccountTokenMetadata(&account)

	return account, nil
}

func attachAccountTokenMetadata(account *model.Account) {
	if account == nil || strings.TrimSpace(account.SavedSessionJSON) == "" {
		return
	}

	var saved session.SavedSession
	if err := json.Unmarshal([]byte(account.SavedSessionJSON), &saved); err != nil {
		return
	}

	account.CKExpiresAt = strings.TrimSpace(saved.TokenInfo.CookieExpiresAt)
}
