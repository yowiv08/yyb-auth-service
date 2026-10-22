package service

import (
	"context"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
)

type operationLocker interface {
	LockOperation(ctx context.Context, unionID string) (func(), error)
}

type accountCoordinator interface {
	operationLocker
	MergeSession(
		ctx context.Context,
		unionID string,
		saved session.SavedSession,
	) (model.Account, error)
}
