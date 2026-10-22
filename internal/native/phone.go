package native

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
)

const (
	getPhoneCGIPath     = "/cgi-bin/mmbiz-bin/wxaapp/customphone/getallphone"
	getPhoneRouteCode   = 2536
	getPhoneTransferCmd = 2536
	getPhoneAPIName     = "webapi_getuserwxphone"
)

type PhoneResult struct {
	OK                  bool                 `json:"ok"`
	Mobile              string               `json:"mobile"`
	ShowMobile          string               `json:"show_mobile"`
	EncryptedData       string               `json:"encryptedData"`
	IV                  string               `json:"iv"`
	Code                string               `json:"code"`
	Data                string               `json:"data,omitempty"`
	CloudID             string               `json:"cloud_id,omitempty"`
	RequestID           string               `json:"request_id,omitempty"`
	ErrorText           string               `json:"error,omitempty"`
	UpdatedSavedSession session.SavedSession `json:"-"`
}

type phonePackedRequest struct {
	Wrapper           []byte
	OutBody           []byte
	Frame             []byte
	Profile           LonglinkProfile
	PackRequestAESKey []byte
	ResponseAESKey    []byte
	ResponseAESKeyAlt []byte
}

func (e *Engine) GetPhone(
	ctx context.Context,
	account model.Account,
	appID string,
) (PhoneResult, error) {
	targetAppID := strings.TrimSpace(appID)
	if targetAppID == "" {
		return PhoneResult{}, fmt.Errorf("appid required")
	}

	account, fresh, err := e.freshLoginBuffer(ctx, account)
	if err != nil {
		return PhoneResult{}, err
	}
	saved, err := buildSavedSession(account)
	if err != nil {
		return PhoneResult{}, err
	}
	result := PhoneResult{
		Mobile:        "",
		ShowMobile:    "",
		EncryptedData: "",
		IV:            "",
		Code:          "",
	}
	finish := func() PhoneResult {
		result.UpdatedSavedSession = saved
		return result
	}

	applyFreshLoginBuffer(&saved, fresh)

	endpoint, err := resolveLonglinkEndpoint(ctx, saved)
	if err != nil {
		return finish(), err
	}
	longlink, err := openLonglinkSession(ctx, endpoint.Host, endpoint.Port, e.timeout, true)
	if err != nil {
		return finish(), err
	}
	defer longlink.Close()

	if strings.TrimSpace(saved.ProtocolDevice.DeviceIDB64) == "" {
		return finish(), fmt.Errorf("account missing protocol device id")
	}
	tdiCtx := buildTDIContext(saved.ProtocolDevice.DeviceIDB64)
	manualRequest, err := buildManualAuthRequest(tdiCtx, fresh.LoginBuffer.Raw)
	if err != nil {
		return finish(), err
	}

	manualStage, err := longlink.SendPackedBody(ctx, PackedStage{
		IdentityMode: "zero",
		Body:         manualRequest.HybridRequest,
		Seq:          3,
		TaskID:       manualAuthCmdID,
		TaskType:     manualAuthTaskType,
		Timeout:      e.timeout,
	})
	if err != nil {
		return finish(), err
	}
	manualResult, err := decodeManualAuthStage(manualStage, manualRequest.RequestState, &saved)
	if err != nil {
		return finish(), err
	}
	if !manualResult.OK {
		return finish(), fmt.Errorf(
			"manualauth failed baseRet=%d authSect=%t msg=%s",
			manualResult.BaseRet,
			manualResult.HasAuthSect,
			firstNonEmpty(manualResult.ErrMsg, "unknown"),
		)
	}

	accessTicket, err := longlink.deriveShortcloudAccessTicket(shortcloudPskTypeType1)
	if err != nil {
		return finish(), err
	}
	phoneRequest, err := buildGetPhoneRequest(targetAppID, manualResult.SessionBlob)
	if err != nil {
		return finish(), err
	}

	shortEndpoint, err := resolveShortcloudEndpoint(ctx, saved)
	if err != nil {
		return finish(), err
	}
	shortRequest, err := buildShortcloudRequestMaterial(
		accessTicket.AccessPSK,
		accessTicket.SelectedPSK,
		phoneRequest.Frame,
	)
	if err != nil {
		return finish(), err
	}

	requestBody := make([]byte, 0,
		len(shortRequest.ClientHelloRecord)+
			len(shortRequest.PrefaceRecord)+
			len(shortRequest.EnvelopeRecord)+
			len(shortRequest.CloseRecord),
	)
	requestBody = append(requestBody, shortRequest.ClientHelloRecord...)
	requestBody = append(requestBody, shortRequest.PrefaceRecord...)
	requestBody = append(requestBody, shortRequest.EnvelopeRecord...)
	requestBody = append(requestBody, shortRequest.CloseRecord...)

	shortResponse, err := sendShortcloudRequest(
		ctx,
		shortEndpoint,
		shortEndpoint.Host,
		shortcloudPathID,
		requestBody,
		e.timeout,
	)
	if err != nil {
		return finish(), err
	}
	if len(shortResponse.Records) == 0 {
		return finish(), nil
	}

	responseKeys := deriveShortcloudResponseKeys(
		accessTicket.AccessPSK,
		shortRequest.ClientHelloRecord,
		shortResponse.Records[0].Raw,
	)

	for seq, record := range shortResponse.Records[1:] {
		if record.RecordType != shortcloudApplicationType {
			continue
		}
		aad := buildAAD(record.RecordType, record.PayloadLen, uint64(seq+1))
		nonce, err := gcmNonce(responseKeys.IV, uint64(seq+1))
		if err != nil {
			return finish(), err
		}
		plain, err := aesGCMDecrypt(responseKeys.Key, nonce, record.Raw[5:], aad)
		if err != nil {
			continue
		}
		body, err := parseTransferFrameBody(plain)
		if err != nil {
			continue
		}
		decoded, ok := decodePhoneRaw89(body, phoneRequest)
		if !ok {
			continue
		}
		result = decoded
		result.UpdatedSavedSession = saved
		return result, nil
	}

	return finish(), nil
}

func buildGetPhoneRequest(
	appID string,
	sessionBlob []byte,
) (phonePackedRequest, error) {
	sessionState, err := parseType5SessionBlob(sessionBlob)
	if err != nil {
		return phonePackedRequest{}, err
	}

	sessionBase := buildSessionBaseRequest(uint32(sessionState.UIN))
	operatePayload, err := json.Marshal(map[string]any{
		"api_name": getPhoneAPIName,
		"data": map[string]any{
			"api_name":         getPhoneAPIName,
			"with_credentials": true,
		},
		"with_credentials": true,
	})
	if err != nil {
		return phonePackedRequest{}, fmt.Errorf("marshal getphone operate payload: %w", err)
	}

	innerBody := buildGetPhoneInnerBody(appID, sessionBase, operatePayload)
	wrapper := buildGetPhoneWrapper(appID, sessionBase, innerBody)

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return phonePackedRequest{}, fmt.Errorf("generate getphone nonce: %w", err)
	}
	outBody, _, err := packOperateWXDataWrapper(
		wrapper,
		sessionState.PackRequestAESKey,
		nonce,
	)
	if err != nil {
		return phonePackedRequest{}, err
	}

	profile := profileFromType5Session(sessionState)
	frame, err := buildTransferFrame(outBody, profile, getPhoneTransferCmd)
	if err != nil {
		return phonePackedRequest{}, err
	}
	return phonePackedRequest{
		Wrapper:           wrapper,
		OutBody:           outBody,
		Frame:             frame,
		Profile:           profile,
		PackRequestAESKey: append([]byte{}, sessionState.PackRequestAESKey...),
		ResponseAESKey:    append([]byte{}, sessionState.ResponseAESKey...),
		ResponseAESKeyAlt: append([]byte{}, sessionState.ResponseAESKeyAlt...),
	}, nil
}

func buildGetPhoneWrapper(
	targetAppID string,
	sessionBase []byte,
	innerBody []byte,
) []byte {
	wrapper := []byte{}
	wrapper = append(wrapper, pbFieldBytes(1, sessionBase)...)
	wrapper = append(wrapper, pbFieldBytes(2, []byte(getPhoneCGIPath))...)
	wrapper = append(wrapper, pbFieldBytes(3, []byte(defaultHostAppID))...)
	wrapper = append(wrapper, pbFieldVarint(4, defaultOuterField4)...)
	wrapper = append(wrapper, pbFieldBytes(5, innerBody)...)
	wrapper = append(wrapper, pbFieldBytes(6, []byte(targetAppID))...)
	wrapper = append(wrapper, pbFieldVarint(7, getPhoneRouteCode)...)
	wrapper = append(wrapper, pbFieldVarint(8, defaultOuterField8)...)
	wrapper = append(wrapper, pbFieldBytes(9, []byte(defaultPlugin))...)
	wrapper = append(wrapper, pbFieldVarint(10, defaultOuterField10)...)
	return wrapper
}

func buildGetPhoneInnerBody(
	targetAppID string,
	sessionBase []byte,
	operatePayload []byte,
) []byte {
	body := []byte{}
	body = append(body, pbFieldBytes(1, sessionBase)...)
	body = append(body, pbFieldBytes(2, []byte(targetAppID))...)
	body = append(body, pbFieldBytes(3, operatePayload)...)
	return body
}

func buildTransferFrame(
	body []byte,
	profile LonglinkProfile,
	cmdID uint32,
) ([]byte, error) {
	outerHeader, err := buildLonglinkPackHeader(profile, "account")
	if err != nil {
		return nil, err
	}
	totalLen := 16 + len(outerHeader) + len(body)
	head := make([]byte, 16)
	binary.BigEndian.PutUint32(head[0:4], uint32(totalLen))
	binary.BigEndian.PutUint32(head[4:8], transferWord1)
	binary.BigEndian.PutUint32(head[8:12], cmdID)
	binary.BigEndian.PutUint32(head[12:16], 0)

	frame := append(head, outerHeader...)
	frame = append(frame, body...)
	return frame, nil
}

func parseTransferFrameBody(frame []byte) ([]byte, error) {
	if len(frame) < 16 {
		return nil, fmt.Errorf("transfer frame too short")
	}
	totalLen := binary.BigEndian.Uint32(frame[0:4])
	if int(totalLen) != len(frame) {
		return nil, fmt.Errorf("transfer frame total length mismatch")
	}
	pack, err := parseLonglinkPackHeader(frame[16:])
	if err != nil {
		return nil, err
	}
	return pack.Body, nil
}

func decodePhoneRaw89(
	raw89 []byte,
	request phonePackedRequest,
) (PhoneResult, bool) {
	keys := []struct {
		key []byte
	}{
		{key: request.ResponseAESKey},
		{key: request.ResponseAESKeyAlt},
		{key: request.PackRequestAESKey},
	}

	for _, row := range keys {
		if len(row.key) == 0 {
			continue
		}
		plain, err := unpackRaw89(raw89, row.key)
		if err != nil {
			continue
		}
		result, ok := extractPhoneResult(plain)
		if ok {
			return result, true
		}
	}
	return PhoneResult{}, false
}

func extractPhoneResult(plain []byte) (PhoneResult, bool) {
	needle := []byte("wx_phone")
	index := strings.Index(string(plain), string(needle))
	if index < 0 {
		return PhoneResult{}, false
	}
	start := strings.LastIndex(string(plain[:index]), "{")
	if start < 0 {
		return PhoneResult{}, false
	}

	depth := 0
	for cursor := start; cursor < len(plain); cursor++ {
		switch plain[cursor] {
		case '{':
			depth++
		case '}':
			depth--
			if depth != 0 {
				continue
			}

			candidate := plain[start : cursor+1]
			var payload map[string]any
			if err := json.Unmarshal(candidate, &payload); err != nil {
				return PhoneResult{}, false
			}
			wxPhone, ok := payload["wx_phone"].(map[string]any)
			if !ok {
				return PhoneResult{}, false
			}
			result := PhoneResult{
				Mobile:        mapString(wxPhone, "mobile"),
				ShowMobile:    mapString(wxPhone, "show_mobile"),
				EncryptedData: mapString(wxPhone, "encryptedData"),
				IV:            mapString(wxPhone, "iv"),
				Data:          mapString(wxPhone, "data"),
				CloudID:       firstNonEmpty(mapString(wxPhone, "cloud_id"), mapString(wxPhone, "cloudID")),
				RequestID:     firstNonEmpty(mapString(wxPhone, "request_id"), mapString(wxPhone, "requestId")),
				Code:          mapString(wxPhone, "code"),
			}
			if result.Data != "" {
				var inner map[string]any
				if err := json.Unmarshal([]byte(result.Data), &inner); err == nil {
					result.Code = firstNonEmpty(result.Code, mapString(inner, "code"))
				}
			}
			result.OK = result.Mobile != ""
			return result, true
		}
	}
	return PhoneResult{}, false
}

func mapString(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}
