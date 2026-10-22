package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
)

const operateWXDataCGI = "/cgi-bin/mmbiz-bin/js-operatewxdata"

const (
	OperateWXDataModeDefault            = ""
	OperateWXDataModeGatewayServiceInfo = "gateway_service_info"
	gatewayServiceInfoRouteCode         = 1030
	gatewayServiceInfoDeviceType        = "Android"
)

type OperateWXDataInput struct {
	AppID       string
	OperateCode int
	DataString  string
	Mode        string
}

type OperateWXDataResult struct {
	OK                  bool                       `json:"ok"`
	AppID               string                     `json:"appid"`
	OperateCode         int                        `json:"operate_code"`
	Request             OperateWXDataRequestTrace  `json:"request"`
	Response            OperateWXDataResponseTrace `json:"response"`
	Decoded             map[string]any             `json:"decoded,omitempty"`
	DecodedRaw          string                     `json:"decoded_raw,omitempty"`
	Plain               []byte                     `json:"-"`
	UpdatedSavedSession session.SavedSession       `json:"-"`
}

type OperateWXDataRequestTrace struct {
	CmdID           uint32 `json:"cmdid"`
	CGI             string `json:"cgi"`
	WrapperLen      int    `json:"wrapper_len"`
	OutBodyLen      int    `json:"out_body_len"`
	PackRoundTripOK bool   `json:"pack_round_trip_ok"`
}

type OperateWXDataResponseTrace struct {
	Source     string `json:"source,omitempty"`
	TaskID     uint32 `json:"task_id,omitempty"`
	Tag4       int64  `json:"tag4"`
	Tag23      int64  `json:"tag23"`
	BodyLen    int    `json:"body_len"`
	DecodeMode string `json:"decode_mode,omitempty"`
	PlainLen   int    `json:"plain_len,omitempty"`
}

type operateWXDataPackedRequest struct {
	Wrapper                 []byte
	OutBody                 []byte
	Profile                 LonglinkProfile
	AESKey                  []byte
	ResponseAESKey          []byte
	ResponseAESKeyAlt       []byte
	ReplayDecryptsToWrapper bool
	TaskID                  uint32
	TaskType                int32
}

type operateWXDataDecoded struct {
	Response   OperateWXDataResponseTrace
	Decoded    map[string]any
	DecodedRaw string
	Plain      []byte
}

func (e *Engine) OperateWXData(
	ctx context.Context,
	account model.Account,
	input OperateWXDataInput,
) (OperateWXDataResult, error) {
	appID := strings.TrimSpace(input.AppID)
	if appID == "" {
		return OperateWXDataResult{}, fmt.Errorf("appid required")
	}
	if input.OperateCode < 0 {
		return OperateWXDataResult{}, fmt.Errorf("operate_code must be >= 0")
	}

	account, fresh, err := e.freshLoginBuffer(ctx, account)
	if err != nil {
		return OperateWXDataResult{}, err
	}
	saved, err := buildSavedSession(account)
	if err != nil {
		return OperateWXDataResult{}, err
	}

	result := OperateWXDataResult{
		AppID:       appID,
		OperateCode: input.OperateCode,
	}
	finish := func() OperateWXDataResult {
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

	operateRequest, err := buildOperateWXDataRequest(
		appID,
		input.OperateCode,
		input.DataString,
		manualResult.SessionBlob,
		input.Mode,
	)
	if err != nil {
		return finish(), err
	}
	result.Request = OperateWXDataRequestTrace{
		CmdID:           operateRequest.TaskID,
		CGI:             operateWXDataCGI,
		WrapperLen:      len(operateRequest.Wrapper),
		OutBodyLen:      len(operateRequest.OutBody),
		PackRoundTripOK: operateRequest.ReplayDecryptsToWrapper,
	}

	stage, err := longlink.SendPackedBody(ctx, PackedStage{
		Profile:      operateRequest.Profile,
		IdentityMode: "account",
		Body:         operateRequest.OutBody,
		Seq:          4,
		TaskID:       operateRequest.TaskID,
		TaskType:     operateRequest.TaskType,
		Timeout:      e.timeout,
	})
	if err != nil {
		return finish(), err
	}

	decoded, err := decodeOperateWXDataStage(stage, operateRequest)
	if err != nil {
		return finish(), err
	}
	result.OK = true
	result.Response = decoded.Response
	result.Decoded = decoded.Decoded
	result.DecodedRaw = decoded.DecodedRaw
	result.Plain = decoded.Plain
	return finish(), nil
}

func buildOperateWXDataRequest(
	appID string,
	operateCode int,
	dataString string,
	sessionBlob []byte,
	mode string,
) (operateWXDataPackedRequest, error) {
	sessionState, err := parseType5SessionBlob(sessionBlob)
	if err != nil {
		return operateWXDataPackedRequest{}, err
	}

	wrapper := buildOperateWXDataWrapper(
		appID,
		uint32(sessionState.UIN),
		operateCode,
		dataString,
		mode,
	)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return operateWXDataPackedRequest{}, fmt.Errorf("generate operatewxdata nonce: %w", err)
	}

	outBody, replayOK, err := packOperateWXDataWrapper(
		wrapper,
		sessionState.PackRequestAESKey,
		nonce,
	)
	if err != nil {
		return operateWXDataPackedRequest{}, err
	}

	return operateWXDataPackedRequest{
		Wrapper:                 wrapper,
		OutBody:                 outBody,
		Profile:                 profileFromType5Session(sessionState),
		AESKey:                  append([]byte{}, sessionState.PackRequestAESKey...),
		ResponseAESKey:          append([]byte{}, sessionState.ResponseAESKey...),
		ResponseAESKeyAlt:       append([]byte{}, sessionState.ResponseAESKeyAlt...),
		ReplayDecryptsToWrapper: replayOK,
		TaskID:                  JSLoginTaskID,
		TaskType:                JSLoginTaskType,
	}, nil
}

func buildOperateWXDataWrapper(
	targetAppID string,
	sessionDynamicField2 uint32,
	operateCode int,
	dataString string,
	mode string,
) []byte {
	sessionBase := buildOperateWXDataSessionBase(sessionDynamicField2, mode)
	innerBody := buildOperateWXDataInnerBody(
		targetAppID,
		sessionBase,
		operateCode,
		dataString,
		mode,
	)
	routeCode := uint64(defaultRouteCode)
	if mode == OperateWXDataModeGatewayServiceInfo {
		routeCode = gatewayServiceInfoRouteCode
	}

	wrapper := []byte{}
	wrapper = append(wrapper, pbFieldBytes(1, sessionBase)...)
	wrapper = append(wrapper, pbFieldBytes(2, []byte(operateWXDataCGI))...)
	wrapper = append(wrapper, pbFieldBytes(3, []byte(defaultHostAppID))...)
	wrapper = append(wrapper, pbFieldVarint(4, defaultOuterField4)...)
	wrapper = append(wrapper, pbFieldBytes(5, innerBody)...)
	wrapper = append(wrapper, pbFieldBytes(6, []byte(targetAppID))...)
	wrapper = append(wrapper, pbFieldVarint(7, routeCode)...)
	wrapper = append(wrapper, pbFieldVarint(8, defaultOuterField8)...)
	wrapper = append(wrapper, pbFieldBytes(9, []byte(defaultPlugin))...)
	wrapper = append(wrapper, pbFieldVarint(10, defaultOuterField10)...)
	return wrapper
}

func buildOperateWXDataInnerBody(
	targetAppID string,
	sessionBase []byte,
	operateCode int,
	dataString string,
	mode string,
) []byte {
	body := []byte{}
	body = append(body, pbFieldBytes(1, sessionBase)...)
	body = append(body, pbFieldBytes(2, []byte(targetAppID))...)
	body = append(body, pbFieldBytes(3, []byte(dataString))...)
	if mode == OperateWXDataModeGatewayServiceInfo {
		body = append(body, pbFieldVarint(5, 0)...)
		body = append(body, pbFieldVarint(6, 0)...)
		return body
	}
	body = append(body, pbFieldVarint(4, uint64(operateCode))...)
	return body
}

func buildOperateWXDataSessionBase(sessionDynamicField2 uint32, mode string) []byte {
	if mode != OperateWXDataModeGatewayServiceInfo {
		return buildSessionBaseRequest(sessionDynamicField2)
	}

	body := []byte{}
	body = append(body, pbFieldBytes(1, []byte("sessionkey"))...)
	body = append(body, pbFieldVarint(2, uint64(sessionDynamicField2))...)
	body = append(body, pbFieldBytes(3, []byte(defaultDeviceMAC))...)
	body = append(body, pbFieldVarint(4, defaultClientVersion)...)
	body = append(body, pbFieldBytes(5, []byte(gatewayServiceInfoDeviceType))...)
	body = append(body, pbFieldVarint(6, 0)...)
	return body
}

func packOperateWXDataWrapper(
	wrapper []byte,
	aesKey []byte,
	nonce []byte,
) ([]byte, bool, error) {
	compressed := lz4CompressBlock(wrapper)
	outBody, err := aesGCMEncrypt192Packed(aesKey, compressed, nonce, nil)
	if err != nil {
		return nil, false, err
	}

	replayOK := false
	replayCompressed, err := aesGCMDecrypt192Packed(aesKey, outBody, nil)
	if err == nil {
		if replayRaw, err := lz4DecompressBlock(replayCompressed); err == nil {
			replayOK = bytes.Equal(replayRaw, wrapper)
		}
	}
	return outBody, replayOK, nil
}

func decodeOperateWXDataStage(
	stage StageResult,
	request operateWXDataPackedRequest,
) (operateWXDataDecoded, error) {
	bodies := responseBodiesFromStage(stage)
	if len(bodies) == 0 {
		return operateWXDataDecoded{}, fmt.Errorf("operatewxdata response missing")
	}

	decryptKeys := []struct {
		label string
		key   []byte
	}{
		{label: "raw89-sessionField2", key: request.ResponseAESKey},
		{label: "raw89-sessionField3", key: request.ResponseAESKeyAlt},
		{label: "raw89-packrequest", key: request.AESKey},
	}

	var firstDecoded *operateWXDataDecoded
	var firstDecryptErr error
	for _, body := range bodies {
		trace := OperateWXDataResponseTrace{
			Source:  body.Source,
			TaskID:  stage.TaskID,
			Tag4:    body.Tag4,
			Tag23:   body.Tag23,
			BodyLen: len(body.Body),
		}
		if len(body.Body) == 0 {
			continue
		}

		for _, row := range decryptKeys {
			if len(row.key) == 0 {
				continue
			}
			plain, err := unpackRaw89(body.Body, row.key)
			if err != nil {
				if firstDecryptErr == nil {
					firstDecryptErr = err
				}
				continue
			}

			decodedRaw, decoded := extractOperateWXDataJSON(plain)
			current := operateWXDataDecoded{
				Response: OperateWXDataResponseTrace{
					Source:     trace.Source,
					TaskID:     trace.TaskID,
					Tag4:       trace.Tag4,
					Tag23:      trace.Tag23,
					BodyLen:    trace.BodyLen,
					DecodeMode: row.label,
					PlainLen:   len(plain),
				},
				Decoded:    decoded,
				DecodedRaw: decodedRaw,
				Plain:      plain,
			}
			if decodedRaw != "" {
				return current, nil
			}
			if firstDecoded == nil {
				firstDecoded = &current
			}
		}

		decodedRaw, decoded := extractOperateWXDataJSON(body.Body)
		if decodedRaw == "" {
			continue
		}
		return operateWXDataDecoded{
			Response: OperateWXDataResponseTrace{
				Source:     trace.Source,
				TaskID:     trace.TaskID,
				Tag4:       trace.Tag4,
				Tag23:      trace.Tag23,
				BodyLen:    trace.BodyLen,
				DecodeMode: "direct-proto",
			},
			Decoded:    decoded,
			DecodedRaw: decodedRaw,
			Plain:      body.Body,
		}, nil
	}

	if firstDecoded != nil {
		return *firstDecoded, nil
	}
	if firstDecryptErr != nil {
		return operateWXDataDecoded{}, fmt.Errorf(
			"decode operatewxdata response: %w",
			firstDecryptErr,
		)
	}
	return operateWXDataDecoded{}, fmt.Errorf("operatewxdata response body empty")
}

func extractOperateWXDataJSON(raw []byte) (string, map[string]any) {
	if decodedRaw, decoded := decodeOperateWXDataJSONObject(raw); decodedRaw != "" {
		return decodedRaw, decoded
	}

	for _, text := range collectProtoStrings(raw, 0) {
		if decodedRaw, decoded := decodeOperateWXDataJSONObject([]byte(text)); decodedRaw != "" {
			return decodedRaw, decoded
		}
	}
	return "", nil
}

func decodeOperateWXDataJSONObject(raw []byte) (string, map[string]any) {
	text := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(text, "{") {
		return "", nil
	}

	decoded := map[string]any{}
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		return "", nil
	}
	if _, ok := decoded["err_no"]; ok {
		return text, decoded
	}
	if _, ok := decoded["data"]; ok {
		return text, decoded
	}
	if _, ok := decoded["baseresponse"]; ok {
		return text, decoded
	}
	return "", nil
}

type LegacyPhoneResult struct {
	OK          bool   `json:"ok"`
	AppID       string `json:"appid"`
	PhoneNumber string `json:"phone_number,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	ErrorText   string `json:"error,omitempty"`
	DecodedRaw  string `json:"decoded_raw,omitempty"`
}

func ExtractPhoneFromPlain(plain []byte) (phoneNumber, countryCode, errorText string) {
	for _, text := range collectProtoStrings(plain, 0) {
		if phoneNumber == "" && isChineseMobile(text) {
			phoneNumber = text
			continue
		}
		isShortDigits := phoneNumber != "" && countryCode == "" &&
			len(text) >= 1 && len(text) <= 4 && isAllDigits(text)
		if isShortDigits {
			countryCode = text
			continue
		}
		lower := strings.ToLower(text)
		isErrorMsg := errorText == "" &&
			(strings.Contains(lower, "invalid") || strings.Contains(lower, "scope") || strings.Contains(lower, "fail"))
		if isErrorMsg {
			errorText = text
		}
	}
	return
}

func isChineseMobile(text string) bool {
	if len(text) != 11 || text[0] != '1' {
		return false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isAllDigits(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func collectProtoStrings(raw []byte, depth int) []string {
	if len(raw) == 0 || depth > 6 {
		return []string{}
	}

	fields, err := pbDecode(raw)
	if err != nil {
		return []string{}
	}

	out := []string{}
	for _, values := range fields {
		for _, value := range values {
			if len(value.Bytes) == 0 {
				continue
			}
			if text := printableASCII(value.Bytes); text != "" {
				out = append(out, text)
			}
			out = append(out, collectProtoStrings(value.Bytes, depth+1)...)
		}
	}
	return out
}
