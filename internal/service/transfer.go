package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/store"
)

const transferTimeout = 75 * time.Second

var ErrTransferAccountNotFound = errors.New("transfer account not found")

func (s *CloudService) Transfer(
	ctx context.Context,
	accountUnionID string,
	input native.TransferInput,
) (native.TransferResult, error) {
	startedAt := time.Now()
	unionID := strings.TrimSpace(accountUnionID)
	appID := strings.TrimSpace(input.AppID)
	cgi := strings.TrimSpace(input.CGI)

	s.logInfo(
		ctx,
		"transfer请求开始",
		slog.String("unionid", unionID),
		slog.String("appid", appID),
		slog.String("cgi", cgi),
		slog.Uint64("route", uint64(input.Route)),
	)

	if unionID == "" {
		err := fmt.Errorf("account unionid required")
		s.logError(ctx, "transfer请求失败", err, startedAt)
		return native.TransferResult{}, err
	}
	if appID == "" {
		err := fmt.Errorf("appid required")
		s.logError(ctx, "transfer请求失败", err, startedAt)
		return native.TransferResult{}, err
	}

	transferCtx, cancel := context.WithTimeout(ctx, transferTimeout)
	defer cancel()
	unlock, err := s.sessions.LockOperation(transferCtx, unionID)
	if err != nil {
		return native.TransferResult{}, fmt.Errorf("lock account operation: %w", err)
	}
	defer unlock()

	account, err := s.accounts.ByUnionID(transferCtx, unionID)
	if err != nil {
		if errors.Is(err, store.ErrAccountNotFound) || errors.Is(err, sql.ErrNoRows) {
			err = fmt.Errorf("%w: %s", ErrTransferAccountNotFound, unionID)
		}
		s.logError(ctx, "transfer请求失败", err, startedAt)
		return native.TransferResult{}, err
	}

	result, transferErr := s.engine.Transfer(transferCtx, account, input)
	if errors.Is(transferErr, context.DeadlineExceeded) {
		transferErr = fmt.Errorf(
			"transfer timed out after %s: %w",
			transferTimeout,
			transferErr,
		)
	}

	if shouldSyncSavedSession(result.UpdatedSavedSession) {
		syncCtx, syncCancel := persistenceContext(ctx)
		_, updateErr := s.sessions.MergeSession(
			syncCtx,
			account.UnionID,
			result.UpdatedSavedSession,
		)
		syncCancel()
		if updateErr != nil {
			if transferErr == nil {
				transferErr = updateErr
			} else {
				s.logError(
					ctx,
					"account session persistence failed",
					updateErr,
					startedAt,
					slog.String("unionid", unionID),
				)
			}
		}
	}

	if transferErr != nil {
		s.logError(ctx, "transfer请求失败", transferErr, startedAt,
			slog.String("unionid", unionID),
			slog.String("appid", appID),
			slog.String("cgi", cgi),
		)
		return result, transferErr
	}

	s.logInfo(
		ctx,
		"transfer请求成功",
		slog.String("unionid", unionID),
		slog.String("appid", appID),
		slog.String("cgi", cgi),
		slog.Uint64("route", uint64(input.Route)),
		slog.String("decode_mode", result.Response.DecodeMode),
		slog.String("decoded_format", result.DecodedFormat),
		slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
	)
	return result, nil
}
