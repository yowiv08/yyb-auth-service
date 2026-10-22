package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"yyb-auth-service/internal/model"
)

type ScanStore struct {
	db *sql.DB
}

func NewScanStore(db *sql.DB) *ScanStore {
	return &ScanStore{db: db}
}

func (s *ScanStore) Create(
	ctx context.Context,
	guid string,
	state string,
	uuid string,
	qrURL string,
) (model.ScanSession, error) {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(
		ctx,
		`
		insert into scan_sessions (
			status,
			guid,
			state,
			uuid,
			qr_url,
			created_at,
			updated_at
		) values (?, ?, ?, ?, ?, ?, ?)
		`,
		"waiting",
		guid,
		state,
		uuid,
		qrURL,
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return model.ScanSession{}, fmt.Errorf("create scan session: %w", err)
	}

	scanID, err := result.LastInsertId()
	if err != nil {
		return model.ScanSession{}, fmt.Errorf("fetch scan session id: %w", err)
	}

	return s.ByID(ctx, scanID)
}

func (s *ScanStore) Update(ctx context.Context, scan model.ScanSession) error {
	scan.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(
		ctx,
		`
		update scan_sessions
		set status = ?,
			guid = ?,
			state = ?,
			uuid = ?,
			qr_url = ?,
			last_errcode = ?,
			wx_code = ?,
			openid = ?,
			unionid = ?,
			account_id = ?,
			error_text = ?,
			updated_at = ?
		where id = ?
		`,
		scan.Status,
		scan.GUID,
		scan.State,
		scan.UUID,
		scan.QRURL,
		scan.LastErrCode,
		scan.WXCode,
		scan.OpenID,
		scan.UnionID,
		scan.AccountID,
		scan.ErrorText,
		scan.UpdatedAt.Format(time.RFC3339Nano),
		scan.ID,
	)
	if err != nil {
		return fmt.Errorf("update scan session: %w", err)
	}
	return nil
}

func (s *ScanStore) ByID(ctx context.Context, scanID int64) (model.ScanSession, error) {
	row := s.db.QueryRowContext(ctx, `select * from scan_sessions where id = ?`, scanID)
	return scanScanSession(row)
}

func scanScanSession(row scanner) (model.ScanSession, error) {
	var (
		scan         model.ScanSession
		accountIDRaw sql.NullInt64
		createdAtRaw string
		updatedAtRaw string
	)

	err := row.Scan(
		&scan.ID,
		&scan.Status,
		&scan.GUID,
		&scan.State,
		&scan.UUID,
		&scan.QRURL,
		&scan.LastErrCode,
		&scan.WXCode,
		&scan.OpenID,
		&scan.UnionID,
		&accountIDRaw,
		&scan.ErrorText,
		&createdAtRaw,
		&updatedAtRaw,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ScanSession{}, fmt.Errorf("scan session not found: %w", err)
		}
		return model.ScanSession{}, fmt.Errorf("scan scan session: %w", err)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, createdAtRaw)
	if err != nil {
		return model.ScanSession{}, fmt.Errorf("parse scan created_at: %w", err)
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, updatedAtRaw)
	if err != nil {
		return model.ScanSession{}, fmt.Errorf("parse scan updated_at: %w", err)
	}

	scan.CreatedAt = createdAt
	scan.UpdatedAt = updatedAt
	if accountIDRaw.Valid {
		accountID := accountIDRaw.Int64
		scan.AccountID = &accountID
	}

	return scan, nil
}
