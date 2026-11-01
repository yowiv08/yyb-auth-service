package native

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
)

const (
	QRConnectAppID = defaultHostAppID
	QRConnectScope = "snsapi_login,snsapi_runtime_pcsdk"
)

type QRConnectResult struct {
	OK                  bool
	Ret                 int64
	ScopeList           []string
	UpdatedSavedSession session.SavedSession
}

func (e *Engine) QRConnectAuthorize(ctx context.Context, account model.Account, uuid string) (QRConnectResult, error) {
	return e.qrConnect(ctx, account, uuid, false)
}

func (e *Engine) QRConnectConfirm(ctx context.Context, account model.Account, uuid string) (QRConnectResult, error) {
	return e.qrConnect(ctx, account, uuid, true)
}

func (e *Engine) qrConnect(ctx context.Context, account model.Account, uuid string, confirm bool) (QRConnectResult, error) {
	input, err := qrConnectTransferInput(uuid, confirm)
	if err != nil {
		return QRConnectResult{}, err
	}
	transferred, err := qrConnectTransferWithRetry(ctx, func() (TransferResult, error) {
		return e.Transfer(ctx, account, input)
	})
	result := QRConnectResult{UpdatedSavedSession: transferred.UpdatedSavedSession}
	if err != nil {
		if transferred.Request.CGI == "" && transferred.ManualAuthRet != nil && *transferred.ManualAuthRet != 0 {
			return result, fmt.Errorf("%w: manualauth ret=%d", ErrOAuthSessionExpired, *transferred.ManualAuthRet)
		}
		return result, err
	}
	if !transferred.OK {
		return result, fmt.Errorf("qrconnect transfer was not successful")
	}
	parsed, err := parseQRConnectResponse(transferred.Plain, confirm)
	if err != nil {
		return result, err
	}
	result.OK, result.Ret = parsed.OK, parsed.Ret
	result.ScopeList = parsed.ScopeList
	return result, nil
}

func parseQRConnectResponse(plain []byte, confirm bool) (QRConnectResult, error) {
	fields, err := pbDecode(plain)
	if err != nil {
		return QRConnectResult{}, fmt.Errorf("decode qrconnect response: %w", err)
	}
	outer, err := parseOAuthBaseResponse(fields)
	if err != nil {
		return QRConnectResult{}, err
	}
	if !outer.OK {
		return QRConnectResult{Ret: outer.Ret}, nil
	}
	if len(firstBytes(fields, 2)) == 0 {
		return QRConnectResult{}, fmt.Errorf("qrconnect response missing business payload")
	}
	businessFields, err := pbDecode(firstBytes(fields, 2))
	if err != nil {
		return QRConnectResult{}, fmt.Errorf("decode qrconnect business payload: %w", err)
	}
	business, err := parseOAuthBaseResponse(businessFields)
	if err != nil {
		return QRConnectResult{}, err
	}
	result := QRConnectResult{OK: business.OK, Ret: business.Ret}
	if !result.OK || confirm {
		return result, nil
	}
	// QRConnect's remaining response fields differ from the public-account
	// OAuth schema. Read only the scopes needed for the confirmation request.
	for _, value := range businessFields[3] {
		if value.WireType != 2 {
			return QRConnectResult{}, fmt.Errorf("qrconnect scope has invalid wire type")
		}
		scope, err := pbDecode(value.Bytes)
		if err != nil {
			return QRConnectResult{}, fmt.Errorf("decode qrconnect scope: %w", err)
		}
		result.ScopeList = append(result.ScopeList, string(firstBytes(scope, 1)))
	}
	return result, nil
}

func qrConnectTransferInput(uuid string, confirm bool) (TransferInput, error) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" || len(uuid) > 128 {
		return TransferInput{}, fmt.Errorf("qrconnect uuid missing or invalid")
	}
	input := TransferInput{
		AppID: QRConnectAppID, CGI: "/cgi-bin/mmbiz-bin/qrconnect_authorize", Route: 1029,
		InnerMode: TransferInnerProtobuf, ResponseMode: TransferResponseProtobuf,
		InnerFields: []TransferProtoField{
			{Number: 1, Kind: TransferProtoSessionBase},
			{Number: 2, Kind: TransferProtoString, Text: "https://open.weixin.qq.com/connect/confirm?uuid=" + url.QueryEscape(uuid)},
		},
	}
	if confirm {
		input.CGI = "/cgi-bin/mmbiz-bin/qrconnect_authorize_confirm"
		input.InnerFields = append(input.InnerFields,
			TransferProtoField{Number: 3, Kind: TransferProtoVarint, Uint: 1},
			TransferProtoField{Number: 4, Kind: TransferProtoString, Text: "snsapi_login"},
			TransferProtoField{Number: 4, Kind: TransferProtoString, Text: "snsapi_runtime_pcsdk"},
			TransferProtoField{Number: 5, Kind: TransferProtoVarint, Uint: 0},
		)
	}
	return input, nil
}

func qrConnectTransferWithRetry(ctx context.Context, attempt func() (TransferResult, error)) (TransferResult, error) {
	var result TransferResult
	var err error
	for index := 0; index < 2; index++ {
		if contextErr := ctx.Err(); contextErr != nil {
			return result, contextErr
		}
		result, err = attempt()
		var packetErr *manualAuthPacketError
		// Only this explicit pre-auth rejection establishes that the business
		// request was not sent. Each attempt obtains fresh one-use auth material.
		retry := index == 0 && result.Request.CGI == "" && errors.As(err, &packetErr) &&
			packetErr.Response.TaskID == manualAuthCmdID && packetErr.Response.TaskType == manualAuthTaskType &&
			packetErr.Response.Tag4 == 0 && packetErr.Response.Tag23 == -20008 && packetErr.Response.BodyLen == 0
		if !retry || ctx.Err() != nil {
			return result, err
		}
	}
	return result, err
}
