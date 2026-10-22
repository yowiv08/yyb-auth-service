package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/store"
)

type ExchangeService struct {
	accounts *store.AccountStore
	engine   *native.Engine
	sessions accountCoordinator
	logger   *slog.Logger
}

const (
	exchangeRunTimeout = 75 * time.Second
	fastStageTimeout   = 15 * time.Second
	persistenceTimeout = 5 * time.Second

	CodeTypeLegacy = 1
	CodeTypeHTTP   = 2
)

func NewExchangeService(
	accounts *store.AccountStore,
	engine *native.Engine,
	sessions accountCoordinator,
	logger *slog.Logger,
) *ExchangeService {
	return &ExchangeService{
		accounts: accounts,
		engine:   engine,
		sessions: sessions,
		logger:   logger,
	}
}

func (s *ExchangeService) ExchangeCode(
	ctx context.Context,
	accountUnionID string,
	appID string,
	codeType int,
) (model.CodeResult, error) {
	startedAt := time.Now()
	codeResult := model.CodeResult{
		UnionID:   accountUnionID,
		AppID:     appID,
		Type:      codeType,
		Status:    "running",
		StartedAt: startedAt.UTC(),
	}
	s.logInfo(
		ctx,
		"小程序code获取开始",
		slog.String("unionid", accountUnionID),
		slog.String("appid", appID),
		slog.Int("type", codeType),
	)

	if codeType != CodeTypeLegacy && codeType != CodeTypeHTTP {
		err := fmt.Errorf("invalid code type %d", codeType)
		s.logError(ctx, "小程序code获取失败", err, startedAt)
		return model.CodeResult{}, err
	}
	exchangeCtx, cancel := context.WithTimeout(ctx, exchangeRunTimeout)
	defer cancel()
	if codeType == CodeTypeLegacy {
		unlock, err := s.sessions.LockOperation(exchangeCtx, accountUnionID)
		if err != nil {
			return model.CodeResult{}, fmt.Errorf("lock account operation: %w", err)
		}
		defer unlock()
	}

	account, err := s.accounts.ByUnionID(exchangeCtx, accountUnionID)
	if err != nil {
		s.logError(ctx, "小程序code获取失败", err, startedAt)
		return model.CodeResult{}, err
	}
	codeResult.UnionID = account.UnionID

	result, exchangeErr := s.exchangeByType(exchangeCtx, account, appID, codeType)
	if errors.Is(exchangeErr, context.DeadlineExceeded) {
		exchangeErr = fmt.Errorf("exchange timed out after %s: %w", exchangeRunTimeout, exchangeErr)
	}

	if codeType == CodeTypeLegacy && (result.UpdatedSavedSession.TokenInfo.OpenID != "" ||
		result.UpdatedSavedSession.GUID != "") {
		syncCtx, syncCancel := persistenceContext(ctx)
		_, updateErr := s.sessions.MergeSession(
			syncCtx,
			account.UnionID,
			result.UpdatedSavedSession,
		)
		syncCancel()
		if updateErr != nil {
			if exchangeErr == nil {
				exchangeErr = updateErr
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

	codeResult.Code = result.Code
	codeResult.FinishedAt = time.Now().UTC()
	if exchangeErr != nil {
		codeResult.Status = "failed"
		codeResult.ErrorText = exchangeErr.Error()
		failureAttrs := []slog.Attr{
			slog.String("unionid", accountUnionID),
			slog.String("appid", appID),
			slog.Int("type", codeType),
		}
		if result.RawResultJSON != "" {
			if summary := compactExchangeTrace(result.RawResultJSON); summary != "" {
				failureAttrs = append(failureAttrs, slog.String("exchange", summary))
			}
		}
		s.logError(
			ctx,
			"小程序code获取失败",
			exchangeErr,
			startedAt,
			failureAttrs...,
		)
		return codeResult, nil
	}

	codeResult.Status = "succeeded"
	s.logInfo(
		ctx,
		"小程序code获取成功",
		slog.String("unionid", accountUnionID),
		slog.String("appid", appID),
		slog.Int("type", codeType),
		slog.String("code", codeResult.Code),
		slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
	)
	return codeResult, nil
}

func compactExchangeTrace(raw string) string {
	var trace struct {
		ManualAuth struct {
			OK             bool   `json:"ok"`
			BaseRet        int    `json:"base_ret"`
			HasAuthSect    bool   `json:"has_auth_sect"`
			HasNetworkSect bool   `json:"has_network_sect"`
			ErrMsg         string `json:"err_msg"`
		} `json:"manualauth"`
		JSLogin struct {
			OK                 bool   `json:"ok"`
			Ret                int64  `json:"ret"`
			ErrMsg             string `json:"errmsg"`
			DecodeMode         string `json:"decode_mode"`
			AttemptCount       int    `json:"attempt_count"`
			EmptyBodies        int    `json:"empty_bodies"`
			DecodeErrors       int    `json:"decode_errors"`
			DecodedWithoutCode int    `json:"decoded_without_code"`
		} `json:"jslogin"`
	}
	if json.Unmarshal([]byte(raw), &trace) != nil {
		return ""
	}
	manualAuth := fmt.Sprintf(
		"manualauth{ret=%d auth=%t network=%t}",
		trace.ManualAuth.BaseRet,
		trace.ManualAuth.HasAuthSect,
		trace.ManualAuth.HasNetworkSect,
	)
	jsLoginNotStarted := !trace.JSLogin.OK && trace.JSLogin.Ret == 0 &&
		trace.JSLogin.ErrMsg == "" && trace.JSLogin.DecodeMode == "" &&
		trace.JSLogin.AttemptCount == 0
	if jsLoginNotStarted {
		return manualAuth
	}
	return fmt.Sprintf(
		"%s; jslogin{ok=%t ret=%d errmsg=%q mode=%s attempts=%d empty=%d decrypt_errors=%d no_code=%d}",
		manualAuth,
		trace.JSLogin.OK, trace.JSLogin.Ret, trace.JSLogin.ErrMsg, trace.JSLogin.DecodeMode,
		trace.JSLogin.AttemptCount, trace.JSLogin.EmptyBodies, trace.JSLogin.DecodeErrors,
		trace.JSLogin.DecodedWithoutCode,
	)
}

func (s *ExchangeService) exchangeByType(
	ctx context.Context,
	account model.Account,
	appID string,
	codeType int,
) (native.Result, error) {
	switch codeType {
	case CodeTypeLegacy:
		return s.engine.ExchangeCode(ctx, account, appID)
	case CodeTypeHTTP:
		return s.exchangeFast(ctx, account, appID)
	default:
		return native.Result{}, fmt.Errorf("invalid code type %d", codeType)
	}
}

func (s *ExchangeService) exchangeFast(
	ctx context.Context,
	account model.Account,
	appID string,
) (native.Result, error) {
	fastCtx, fastCancel := context.WithTimeout(ctx, fastStageTimeout)
	defer fastCancel()
	return s.engine.ExchangeCodeHTTP(fastCtx, account, appID)
}

func persistenceContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), persistenceTimeout)
}

func (s *ExchangeService) logInfo(ctx context.Context, msg string, attrs ...slog.Attr) {
	if s.logger == nil {
		return
	}
	s.logger.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
}

func (s *ExchangeService) logError(
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
