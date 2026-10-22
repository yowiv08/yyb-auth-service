package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/store"
	"yyb-auth-service/internal/yyb"
)

const scanSessionTimeout = 2 * time.Minute
const scanPollInterval = 2 * time.Second
const scanAutoPollTimeout = scanSessionTimeout + 45*time.Second

type scanClient interface {
	StartScan(ctx context.Context) (yyb.ScanInit, error)
	PollScan(
		ctx context.Context,
		uuid string,
		lastErrCode string,
	) (yyb.ScanPollResult, error)
	ExchangeOAuth(ctx context.Context, guid string, wxCode string) (yyb.OAuthResult, error)
	GetUnionID(ctx context.Context, openID string, accessToken string) (string, error)
	GetLoginBuffer(
		ctx context.Context,
		creds yyb.OAuthResult,
		guid string,
		unionID string,
	) (yyb.LoginBuffer, error)
}

type ScanService struct {
	scans        *store.ScanStore
	accounts     *AccountService
	client       scanClient
	logger       *slog.Logger
	pollInterval time.Duration
}

func NewScanService(
	scans *store.ScanStore,
	accounts *AccountService,
	client scanClient,
	logger *slog.Logger,
) *ScanService {
	return &ScanService{
		scans:        scans,
		accounts:     accounts,
		client:       client,
		logger:       logger,
		pollInterval: scanPollInterval,
	}
}

func (s *ScanService) Start(ctx context.Context) (model.ScanSession, error) {
	startedAt := time.Now()
	init, err := s.client.StartScan(ctx)
	if err != nil {
		s.logScanError(ctx, "扫码会话创建失败", 0, "", err, startedAt)
		return model.ScanSession{}, fmt.Errorf("start scan: %w", err)
	}

	scan, err := s.scans.Create(
		ctx,
		init.GUID,
		init.State,
		init.UUID,
		init.QRURL,
	)
	if err != nil {
		s.logScanError(ctx, "扫码会话创建失败", 0, "", err, startedAt)
		return model.ScanSession{}, err
	}

	s.logInfo(
		ctx,
		"扫码会话已创建",
		slog.Int64("scan_id", scan.ID),
		slog.String("uuid", scan.UUID),
		slog.String("expires_at", scan.CreatedAt.Add(scanSessionTimeout).Format(time.RFC3339Nano)),
		slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
	)
	s.startAutoPolling(ctx, scan.ID)
	return attachScanMetadata(scan), nil
}

func (s *ScanService) Get(ctx context.Context, scanID int64) (model.ScanSession, error) {
	scan, err := s.scans.ByID(ctx, scanID)
	if err != nil {
		return model.ScanSession{}, err
	}
	return s.attachScanAccountMetadata(ctx, attachScanMetadata(scan)), nil
}

func (s *ScanService) startAutoPolling(ctx context.Context, scanID int64) {
	pollCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		scanAutoPollTimeout,
	)

	go func() {
		defer cancel()
		s.logInfo(
			pollCtx,
			"扫码自动轮询开始",
			slog.Int64("scan_id", scanID),
			slog.String("poll_interval", scanPollInterval.String()),
			slog.String("timeout", scanAutoPollTimeout.String()),
		)
		s.pollUntilTerminal(pollCtx, scanID)
	}()
}

func (s *ScanService) pollUntilTerminal(ctx context.Context, scanID int64) {
	startedAt := time.Now()
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		scan, err := s.poll(ctx, scanID)
		if err != nil {
			s.logScanError(ctx, "扫码自动轮询失败", scanID, "", err, startedAt)
			return
		}
		if isTerminalScanStatus(scan.Status) {
			s.logInfo(
				ctx,
				"扫码自动轮询结束",
				slog.Int64("scan_id", scanID),
				slog.String("status", scan.Status),
				slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
			)
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *ScanService) poll(ctx context.Context, scanID int64) (model.ScanSession, error) {
	scan, err := s.scans.ByID(ctx, scanID)
	if err != nil {
		return model.ScanSession{}, err
	}
	if shouldExpireScan(scan, time.Now().UTC()) {
		return s.expireScan(ctx, scan)
	}
	if isTerminalScanStatus(scan.Status) {
		return attachScanMetadata(scan), nil
	}

	poll, err := s.client.PollScan(ctx, scan.UUID, scan.LastErrCode)
	if err != nil {
		return s.failScan(ctx, scan, fmt.Errorf("poll scan: %w", err))
	}

	oldStatus := scan.Status
	scan.LastErrCode = poll.ErrCode
	scan.WXCode = poll.WXCode
	scan.Status = statusFromPoll(poll.ErrCode, poll.WXCode)
	scan.ErrorText = ""
	s.logScanStatus(ctx, scan, oldStatus)

	if scan.WXCode == "" {
		if err := s.scans.Update(ctx, scan); err != nil {
			return model.ScanSession{}, err
		}
		updated, err := s.scans.ByID(ctx, scan.ID)
		if err != nil {
			return model.ScanSession{}, err
		}
		return attachScanMetadata(updated), nil
	}

	return s.complete(ctx, scan)
}

func (s *ScanService) complete(
	ctx context.Context,
	scan model.ScanSession,
) (model.ScanSession, error) {
	oauth, err := s.client.ExchangeOAuth(ctx, scan.GUID, scan.WXCode)
	if err != nil {
		return s.failScan(ctx, scan, fmt.Errorf("exchange oauth: %w", err))
	}

	unionID, err := s.client.GetUnionID(ctx, oauth.OpenID, oauth.AccessToken)
	if err != nil {
		return s.failScan(ctx, scan, fmt.Errorf("get unionid: %w", err))
	}

	loginBuffer, err := s.client.GetLoginBuffer(ctx, oauth, scan.GUID, unionID)
	if err != nil {
		return s.failScan(ctx, scan, fmt.Errorf("get login buffer: %w", err))
	}
	persistCtx, cancel := persistenceContext(ctx)
	defer cancel()

	account, err := s.accounts.UpsertScannedSession(
		persistCtx,
		ScannedOAuthSession{
			GUID:            scan.GUID,
			State:           scan.State,
			WXCode:          scan.WXCode,
			OpenID:          oauth.OpenID,
			AccessToken:     oauth.AccessToken,
			RefreshToken:    oauth.RefreshToken,
			CookieExpiresAt: oauth.CookieExpiresAt,
			LoginType:       "WX",
			UnionID:         unionID,
			LoginBuffer:     loginBuffer.Raw,
			LoginBufferParsed: map[string]any{
				"authcode":   loginBuffer.AuthCode,
				"ilinkAppid": loginBuffer.IlinkAppID,
				"mpAppid":    loginBuffer.MPAppID,
			},
		},
	)
	if err != nil {
		return s.failScan(ctx, scan, fmt.Errorf("save scanned account: %w", err))
	}

	oldStatus := scan.Status
	scan.Status = "completed"
	scan.OpenID = oauth.OpenID
	scan.UnionID = unionID
	scan.AccountUnionID = account.UnionID
	scan.ErrorText = ""
	scan.AccountID = &account.ID

	if err := s.scans.Update(persistCtx, scan); err != nil {
		return model.ScanSession{}, err
	}
	s.logScanStatus(ctx, scan, oldStatus)
	s.logInfo(
		ctx,
		"扫码登录已完成",
		slog.Int64("scan_id", scan.ID),
		slog.String("account_unionid", scan.AccountUnionID),
	)
	updated, err := s.scans.ByID(persistCtx, scan.ID)
	if err != nil {
		return model.ScanSession{}, err
	}
	return s.attachScanAccountMetadata(persistCtx, attachScanMetadata(updated)), nil
}

func (s *ScanService) attachScanAccountMetadata(
	ctx context.Context,
	scan model.ScanSession,
) model.ScanSession {
	if scan.AccountID == nil {
		return scan
	}

	account, err := s.accounts.ByID(ctx, *scan.AccountID)
	if err != nil {
		return scan
	}
	scan.CKExpiresAt = account.CKExpiresAt
	return scan
}

func (s *ScanService) failScan(
	ctx context.Context,
	scan model.ScanSession,
	err error,
) (model.ScanSession, error) {
	oldStatus := scan.Status
	scan.Status = "failed"
	scan.ErrorText = err.Error()
	persistCtx, cancel := persistenceContext(ctx)
	defer cancel()
	if updateErr := s.scans.Update(persistCtx, scan); updateErr != nil {
		return model.ScanSession{}, fmt.Errorf(
			"%v; additionally update scan session: %w",
			err,
			updateErr,
		)
	}
	s.logScanStatus(ctx, scan, oldStatus)
	return attachScanMetadata(scan), err
}

func isTerminalScanStatus(status string) bool {
	switch status {
	case "canceled", "completed", "expired", "failed":
		return true
	default:
		return false
	}
}

func statusFromPoll(errCode string, wxCode string) string {
	if wxCode != "" {
		return "authorized"
	}

	switch errCode {
	case "404", "405":
		return "scanned"
	case "403":
		return "canceled"
	case "402":
		return "expired"
	default:
		return "waiting"
	}
}

func (s *ScanService) expireScan(
	ctx context.Context,
	scan model.ScanSession,
) (model.ScanSession, error) {
	oldStatus := scan.Status
	scan.Status = "expired"
	scan.LastErrCode = "402"
	scan.ErrorText = ""
	if err := s.scans.Update(ctx, scan); err != nil {
		return model.ScanSession{}, err
	}
	s.logScanStatus(ctx, scan, oldStatus)

	updated, err := s.scans.ByID(ctx, scan.ID)
	if err != nil {
		return model.ScanSession{}, err
	}
	return attachScanMetadata(updated), nil
}

func (s *ScanService) logScanStatus(
	ctx context.Context,
	scan model.ScanSession,
	oldStatus string,
) {
	if scan.Status == oldStatus {
		return
	}

	s.logInfo(
		ctx,
		"扫码状态已更新",
		slog.Int64("scan_id", scan.ID),
		slog.String("old_status", oldStatus),
		slog.String("new_status", scan.Status),
		slog.String("errcode", scan.LastErrCode),
		slog.String("error", scan.ErrorText),
	)
}

func (s *ScanService) logScanError(
	ctx context.Context,
	msg string,
	scanID int64,
	status string,
	err error,
	startedAt time.Time,
) {
	if s.logger == nil {
		return
	}

	attrs := []slog.Attr{
		slog.Any("error", err),
		slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
	}
	if scanID > 0 {
		attrs = append(attrs, slog.Int64("scan_id", scanID))
	}
	if status != "" {
		attrs = append(attrs, slog.String("status", status))
	}

	s.logger.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}

func (s *ScanService) logInfo(ctx context.Context, msg string, attrs ...slog.Attr) {
	if s.logger == nil {
		return
	}
	s.logger.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
}

func shouldExpireScan(scan model.ScanSession, now time.Time) bool {
	if isTerminalScanStatus(scan.Status) {
		return false
	}
	if scan.WXCode != "" {
		return false
	}

	expiresAt := scan.CreatedAt.Add(scanSessionTimeout)
	return !now.Before(expiresAt)
}

func attachScanMetadata(scan model.ScanSession) model.ScanSession {
	scan.ExpiresAt = scan.CreatedAt.Add(scanSessionTimeout)
	if scan.AccountID != nil && scan.AccountUnionID == "" {
		scan.AccountUnionID = scan.UnionID
	}
	if shouldExpireScan(scan, time.Now().UTC()) {
		scan.Status = "expired"
		if scan.LastErrCode == "" {
			scan.LastErrCode = "402"
		}
	}
	return scan
}
