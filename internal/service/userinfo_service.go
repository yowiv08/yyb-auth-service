package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/yyb"
)

const (
	defaultUserInfoLang = "zh_CN"
	userInfoTimeout     = 20 * time.Second
)

type UserInfoService struct {
	accounts userInfoAccounts
	client   userInfoClient
}

type userInfoAccounts interface {
	LockOperation(ctx context.Context, unionID string) (func(), error)
	Account(ctx context.Context, unionID string) (model.Account, error)
	RecoverExpired(
		ctx context.Context,
		unionID string,
		rejectedAccessToken string,
	) (model.Account, error)
}

type userInfoClient interface {
	GetUserInfo(
		ctx context.Context,
		accessToken string,
		openID string,
		lang string,
	) (yyb.UserInfo, error)
}

type UserInfoResult struct {
	OK         bool
	UnionID    string
	OpenID     string
	Nickname   string
	HeadImgURL string
	Sex        int
	Country    string
	Province   string
	City       string
	Privilege  []string
	ErrCode    int
	ErrMsg     string
}

func NewUserInfoService(
	accounts userInfoAccounts,
	client userInfoClient,
) *UserInfoService {
	return &UserInfoService{
		accounts: accounts,
		client:   client,
	}
}

func (s *UserInfoService) Get(
	ctx context.Context,
	accountUnionID string,
	lang string,
) (UserInfoResult, error) {
	unionID := strings.TrimSpace(accountUnionID)
	if unionID == "" {
		return UserInfoResult{}, fmt.Errorf("unionid 必填")
	}
	normalizedLang, err := normalizeUserInfoLang(lang)
	if err != nil {
		return UserInfoResult{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, userInfoTimeout)
	defer cancel()
	unlock, err := s.accounts.LockOperation(requestCtx, unionID)
	if err != nil {
		return UserInfoResult{}, fmt.Errorf("锁定账号操作: %w", err)
	}
	defer unlock()

	account, err := s.accounts.Account(requestCtx, unionID)
	if err != nil {
		return UserInfoResult{}, err
	}
	if strings.TrimSpace(account.OpenID) == "" {
		return UserInfoResult{}, fmt.Errorf("账号缺少 openid")
	}
	if strings.TrimSpace(account.AccessToken) == "" {
		return UserInfoResult{}, fmt.Errorf("账号缺少 access_token")
	}

	userInfo, err := s.client.GetUserInfo(
		requestCtx,
		account.AccessToken,
		account.OpenID,
		normalizedLang,
	)
	shouldRecover := isExpiredUserInfoToken(userInfo.ErrCode) ||
		yyb.IsHTTPStatus(err, 401) ||
		yyb.IsHTTPStatus(err, 403)
	if err != nil && !shouldRecover {
		return UserInfoResult{}, fmt.Errorf("请求微信 userinfo: %w", err)
	}
	if shouldRecover {
		rejection := err
		if userInfo.ErrCode != 0 {
			rejection = errors.Join(rejection, &yyb.BusinessError{
				Operation: "wechat userinfo",
				Code:      userInfo.ErrCode,
				Message:   userInfo.ErrMsg,
			})
		}
		account, err = s.accounts.RecoverExpired(
			requestCtx,
			unionID,
			account.AccessToken,
		)
		if err != nil {
			return UserInfoResult{}, errors.Join(rejection, fmt.Errorf("刷新 userinfo token: %w", err))
		}
		userInfo, err = s.client.GetUserInfo(
			requestCtx,
			account.AccessToken,
			account.OpenID,
			normalizedLang,
		)
		if err != nil {
			return UserInfoResult{}, fmt.Errorf("重试微信 userinfo: %w", err)
		}
	}

	return makeUserInfoResult(account.UnionID, account.OpenID, userInfo), nil
}

func isExpiredUserInfoToken(errCode int) bool {
	return errCode == 40001 || errCode == 40014 || errCode == 42001
}

func normalizeUserInfoLang(lang string) (string, error) {
	trimmed := strings.TrimSpace(lang)
	if trimmed == "" {
		return defaultUserInfoLang, nil
	}

	switch trimmed {
	case "zh_CN", "zh_TW", "en":
		return trimmed, nil
	default:
		return "", fmt.Errorf("lang 仅支持 zh_CN、zh_TW 或 en")
	}
}

func makeUserInfoResult(
	accountUnionID string,
	accountOpenID string,
	userInfo yyb.UserInfo,
) UserInfoResult {
	privilege := append([]string{}, userInfo.Privilege...)
	if privilege == nil {
		privilege = []string{}
	}

	openID := firstNonEmpty(userInfo.OpenID, accountOpenID)
	unionID := firstNonEmpty(userInfo.UnionID, accountUnionID)
	return UserInfoResult{
		OK:         userInfo.ErrCode == 0 && strings.TrimSpace(userInfo.OpenID) != "",
		UnionID:    unionID,
		OpenID:     openID,
		Nickname:   userInfo.Nickname,
		HeadImgURL: userInfo.HeadImgURL,
		Sex:        userInfo.Sex,
		Country:    userInfo.Country,
		Province:   userInfo.Province,
		City:       userInfo.City,
		Privilege:  privilege,
		ErrCode:    userInfo.ErrCode,
		ErrMsg:     userInfo.ErrMsg,
	}
}
