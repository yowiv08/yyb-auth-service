package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/session"
	"yyb-auth-service/internal/store"
)

const operateWXDataTimeout = 75 * time.Second

type CloudService struct {
	accounts *store.AccountStore
	engine   *native.Engine
	sessions accountCoordinator
	logger   *slog.Logger
}

func NewCloudService(
	accounts *store.AccountStore,
	engine *native.Engine,
	sessions accountCoordinator,
	logger *slog.Logger,
) *CloudService {
	return &CloudService{
		accounts: accounts,
		engine:   engine,
		sessions: sessions,
		logger:   logger,
	}
}

func (s *CloudService) OperateWXData(
	ctx context.Context,
	accountUnionID string,
	appID string,
	operateCode int,
	dataString string,
	mode string,
) (native.OperateWXDataResult, error) {
	startedAt := time.Now()
	s.logInfo(
		ctx,
		"operateWXData请求开始",
		slog.String("unionid", accountUnionID),
		slog.String("appid", appID),
		slog.Int("operate_code", operateCode),
	)

	if strings.TrimSpace(accountUnionID) == "" {
		err := fmt.Errorf("account unionid required")
		s.logError(ctx, "operateWXData请求失败", err, startedAt)
		return native.OperateWXDataResult{}, err
	}
	if strings.TrimSpace(appID) == "" {
		err := fmt.Errorf("appid required")
		s.logError(ctx, "operateWXData请求失败", err, startedAt)
		return native.OperateWXDataResult{}, err
	}
	operateCtx, cancel := context.WithTimeout(ctx, operateWXDataTimeout)
	defer cancel()
	unlock, err := s.sessions.LockOperation(operateCtx, accountUnionID)
	if err != nil {
		return native.OperateWXDataResult{}, fmt.Errorf("lock account operation: %w", err)
	}
	defer unlock()

	account, err := s.accounts.ByUnionID(operateCtx, accountUnionID)
	if err != nil {
		s.logError(ctx, "operateWXData请求失败", err, startedAt)
		return native.OperateWXDataResult{}, err
	}

	result, operateErr := s.engine.OperateWXData(
		operateCtx,
		account,
		native.OperateWXDataInput{
			AppID:       appID,
			OperateCode: operateCode,
			DataString:  dataString,
			Mode:        mode,
		},
	)
	if errors.Is(operateErr, context.DeadlineExceeded) {
		operateErr = fmt.Errorf(
			"operatewxdata timed out after %s: %w",
			operateWXDataTimeout,
			operateErr,
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
			if operateErr == nil {
				operateErr = updateErr
			} else {
				s.logError(
					ctx,
					"account session persistence failed",
					updateErr,
					startedAt,
					slog.String("unionid", accountUnionID),
				)
			}
		}
	}

	if operateErr != nil {
		s.logError(ctx, "operateWXData请求失败", operateErr, startedAt)
		return result, operateErr
	}

	s.logInfo(
		ctx,
		"operateWXData请求成功",
		slog.String("unionid", accountUnionID),
		slog.String("appid", appID),
		slog.Int("operate_code", operateCode),
		slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
	)
	return result, operateErr
}

func (s *CloudService) GetPhoneNumber(
	ctx context.Context,
	accountUnionID string,
	appID string,
) (native.PhoneResult, error) {
	startedAt := time.Now()
	s.logInfo(ctx, "getPhoneNumber请求开始",
		slog.String("unionid", accountUnionID),
		slog.String("appid", appID),
	)

	unionID := strings.TrimSpace(accountUnionID)
	if unionID == "" {
		err := fmt.Errorf("account unionid required")
		s.logError(ctx, "getPhoneNumber请求失败", err, startedAt)
		return native.PhoneResult{}, err
	}
	targetAppID := strings.TrimSpace(appID)
	if targetAppID == "" {
		err := fmt.Errorf("appid required")
		s.logError(ctx, "getPhoneNumber请求失败", err, startedAt)
		return native.PhoneResult{}, err
	}
	operateCtx, cancel := context.WithTimeout(ctx, operateWXDataTimeout)
	defer cancel()
	unlock, err := s.sessions.LockOperation(operateCtx, unionID)
	if err != nil {
		return native.PhoneResult{}, fmt.Errorf("lock account operation: %w", err)
	}
	defer unlock()

	account, err := s.accounts.ByUnionID(operateCtx, unionID)
	if err != nil {
		s.logError(ctx, "getPhoneNumber请求失败", err, startedAt)
		return native.PhoneResult{}, err
	}
	if strings.TrimSpace(account.OpenID) == "" {
		err := fmt.Errorf("account missing openid")
		s.logError(ctx, "getPhoneNumber请求失败", err, startedAt,
			slog.String("unionid", unionID),
		)
		return native.PhoneResult{}, err
	}

	phone, operateErr := s.engine.GetPhone(operateCtx, account, targetAppID)

	if shouldSyncSavedSession(phone.UpdatedSavedSession) {
		syncCtx, syncCancel := persistenceContext(ctx)
		_, updateErr := s.sessions.MergeSession(
			syncCtx,
			account.UnionID,
			phone.UpdatedSavedSession,
		)
		syncCancel()
		if updateErr != nil {
			if phone.ErrorText == "" && operateErr == nil {
				phone.ErrorText = updateErr.Error()
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

	if operateErr != nil {
		if errors.Is(operateErr, context.DeadlineExceeded) {
			operateErr = fmt.Errorf(
				"getphonenumber timed out after %s: %w",
				operateWXDataTimeout,
				operateErr,
			)
		}
		phone.ErrorText = firstNonEmpty(phone.ErrorText, operateErr.Error())
		s.logError(ctx, "getPhoneNumber请求失败", operateErr, startedAt,
			slog.String("unionid", unionID),
			slog.String("openid", account.OpenID),
			slog.String("appid", targetAppID),
		)
		return phone, nil
	}

	s.logInfo(ctx, "getPhoneNumber请求完成",
		slog.String("unionid", unionID),
		slog.String("openid", account.OpenID),
		slog.String("appid", targetAppID),
		slog.Bool("ok", phone.OK),
		slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
	)
	return phone, nil
}

func shouldSyncSavedSession(saved session.SavedSession) bool {
	return saved.TokenInfo.OpenID != "" || saved.GUID != ""
}

func (s *CloudService) logInfo(ctx context.Context, msg string, attrs ...slog.Attr) {
	if s.logger == nil {
		return
	}
	s.logger.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
}

func (s *CloudService) logError(
	ctx context.Context,
	msg string,
	err error,
	startedAt time.Time,
	attrs ...slog.Attr,
) {
	if s.logger == nil {
		return
	}

	attrs = append(
		attrs,
		slog.Any("error", err),
		slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
	)
	s.logger.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}
