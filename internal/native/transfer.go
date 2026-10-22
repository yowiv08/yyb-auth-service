package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
)

type TransferDataFormat string

const (
	TransferDataNone   TransferDataFormat = "none"
	TransferDataJSON   TransferDataFormat = "json"
	TransferDataText   TransferDataFormat = "text"
	TransferDataBase64 TransferDataFormat = "base64"
)

type TransferInnerMode string

const (
	TransferInnerStandard TransferInnerMode = "standard"
	TransferInnerProtobuf TransferInnerMode = "protobuf"
	TransferInnerRaw      TransferInnerMode = "raw"
)

type TransferResponseMode string

const (
	TransferResponseAuto     TransferResponseMode = "auto"
	TransferResponseJSON     TransferResponseMode = "json"
	TransferResponseProtobuf TransferResponseMode = "protobuf"
	TransferResponseRaw      TransferResponseMode = "raw"
)

type TransferProtoFieldKind string

const (
	TransferProtoSessionBase TransferProtoFieldKind = "session_base"
	TransferProtoTargetAppID TransferProtoFieldKind = "target_appid"
	TransferProtoHostAppID   TransferProtoFieldKind = "host_appid"
	TransferProtoIlinkAppID  TransferProtoFieldKind = "ilink_appid"
	TransferProtoString      TransferProtoFieldKind = "string"
	TransferProtoBytes       TransferProtoFieldKind = "bytes"
	TransferProtoVarint      TransferProtoFieldKind = "varint"
	TransferProtoFixed32     TransferProtoFieldKind = "fixed32"
	TransferProtoFixed64     TransferProtoFieldKind = "fixed64"
)

const transferInnerBodyLimit = 8 << 20

type TransferProtoField struct {
	Number uint32
	Kind   TransferProtoFieldKind
	Text   string
	Bytes  []byte
	Uint   uint64
}

type TransferOuterOptions struct {
	HostAppID string
	Field4    *uint64
	Field8    *uint64
	Plugin    *string
	Field10   *uint64
}

type TransferTransportOptions struct {
	Sequence     uint64
	TaskID       uint32
	TaskType     *int32
	IdentityMode string
}

type TransferInput struct {
	AppID           string
	CGI             string
	Route           uint32
	Data            []byte
	HasData         bool
	InnerMode       TransferInnerMode
	InnerFields     []TransferProtoField
	RawInnerBody    []byte
	RawInnerBodySet bool
	Outer           TransferOuterOptions
	Transport       TransferTransportOptions
	ResponseMode    TransferResponseMode
}

type TransferRequestTrace struct {
	CGI             string `json:"cgi"`
	Route           uint32 `json:"route"`
	Sequence        uint64 `json:"sequence"`
	TaskID          uint32 `json:"task_id"`
	TaskType        int32  `json:"task_type"`
	IdentityMode    string `json:"identity_mode"`
	InnerMode       string `json:"inner_mode"`
	InnerBodyLen    int    `json:"inner_body_len"`
	HostAppID       string `json:"host_appid"`
	OuterField4     uint64 `json:"outer_field4"`
	OuterField8     uint64 `json:"outer_field8"`
	Plugin          string `json:"plugin"`
	OuterField10    uint64 `json:"outer_field10"`
	WrapperLen      int    `json:"wrapper_len"`
	OutBodyLen      int    `json:"out_body_len"`
	PackRoundTripOK bool   `json:"pack_round_trip_ok"`
}

type TransferResponseTrace struct {
	Source     string `json:"source,omitempty"`
	Sequence   uint64 `json:"sequence,omitempty"`
	TaskID     uint32 `json:"task_id,omitempty"`
	TaskType   int32  `json:"task_type"`
	Tag4       int64  `json:"tag4"`
	Tag23      int64  `json:"tag23"`
	BodyLen    int    `json:"body_len"`
	DecodeMode string `json:"decode_mode,omitempty"`
	PlainLen   int    `json:"plain_len,omitempty"`
}

type TransferResult struct {
	OK                  bool                  `json:"ok"`
	AppID               string                `json:"appid"`
	CGI                 string                `json:"cgi"`
	Route               uint32                `json:"route"`
	Request             TransferRequestTrace  `json:"request"`
	Response            TransferResponseTrace `json:"response"`
	Decoded             any                   `json:"decoded,omitempty"`
	DecodedFormat       string                `json:"decoded_format,omitempty"`
	DecodedRaw          string                `json:"decoded_raw,omitempty"`
	Plain               []byte                `json:"-"`
	UpdatedSavedSession session.SavedSession  `json:"-"`
}

type transferEnvelopeSpec struct {
	CGI          string
	TargetAppID  string
	HostAppID    string
	Route        uint32
	InnerBody    []byte
	OuterField4  uint64
	OuterField8  uint64
	Plugin       string
	OuterField10 uint64
}

type transferPackedRequest struct {
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

type transferDecodedResponse struct {
	Trace      TransferResponseTrace
	Decoded    any
	Format     string
	DecodedRaw string
	Plain      []byte
}

type TransferProtoDecoded struct {
	Format         string                      `json:"format"`
	Fields         []TransferProtoDecodedField `json:"fields"`
	Strings        []string                    `json:"strings"`
	CodeCandidates []string                    `json:"code_candidates"`
}

type TransferProtoDecodedField struct {
	Number  uint32                      `json:"number"`
	Wire    string                      `json:"wire"`
	Varint  *uint64                     `json:"varint,omitempty"`
	Fixed32 *uint32                     `json:"fixed32,omitempty"`
	Fixed64 *uint64                     `json:"fixed64,omitempty"`
	Text    string                      `json:"text,omitempty"`
	Base64  string                      `json:"base64,omitempty"`
	Nested  []TransferProtoDecodedField `json:"nested,omitempty"`
}

func (e *Engine) Transfer(
	ctx context.Context,
	account model.Account,
	input TransferInput,
) (TransferResult, error) {
	appID := strings.TrimSpace(input.AppID)
	cgi := strings.TrimSpace(input.CGI)
	if appID == "" {
		return TransferResult{}, fmt.Errorf("appid required")
	}
	if err := validateTransferCGI(cgi); err != nil {
		return TransferResult{}, err
	}
	if input.Route == 0 {
		return TransferResult{}, fmt.Errorf("route must be greater than 0")
	}

	innerMode := input.InnerMode
	if innerMode == "" {
		innerMode = TransferInnerStandard
	}
	switch innerMode {
	case TransferInnerStandard, TransferInnerProtobuf, TransferInnerRaw:
	default:
		return TransferResult{}, fmt.Errorf("inner mode must be standard, protobuf or raw")
	}

	responseMode := input.ResponseMode
	if responseMode == "" {
		responseMode = TransferResponseAuto
	}
	switch responseMode {
	case TransferResponseAuto, TransferResponseJSON, TransferResponseProtobuf, TransferResponseRaw:
	default:
		return TransferResult{}, fmt.Errorf("response mode must be auto, json, protobuf or raw")
	}

	identityMode := strings.TrimSpace(input.Transport.IdentityMode)
	if identityMode == "" {
		identityMode = "account"
	}
	if identityMode != "account" && identityMode != "zero" {
		return TransferResult{}, fmt.Errorf("identity mode must be account or zero")
	}
	sequence := input.Transport.Sequence
	if sequence == 0 {
		sequence = 4
	}
	taskID := input.Transport.TaskID
	if taskID == 0 {
		taskID = JSLoginTaskID
	}
	taskType := int32(JSLoginTaskType)
	if input.Transport.TaskType != nil {
		taskType = *input.Transport.TaskType
	}

	hostAppID := strings.TrimSpace(input.Outer.HostAppID)
	if hostAppID == "" {
		hostAppID = defaultHostAppID
	}
	outerField4 := uint64(defaultOuterField4)
	if input.Outer.Field4 != nil {
		outerField4 = *input.Outer.Field4
	}
	outerField8 := uint64(defaultOuterField8)
	if input.Outer.Field8 != nil {
		outerField8 = *input.Outer.Field8
	}
	plugin := defaultPlugin
	if input.Outer.Plugin != nil {
		plugin = *input.Outer.Plugin
	}
	outerField10 := uint64(defaultOuterField10)
	if input.Outer.Field10 != nil {
		outerField10 = *input.Outer.Field10
	}

	account, fresh, err := e.freshLoginBuffer(ctx, account)
	if err != nil {
		return TransferResult{}, err
	}
	saved, err := buildSavedSession(account)
	if err != nil {
		return TransferResult{}, err
	}

	result := TransferResult{AppID: appID, CGI: cgi, Route: input.Route}
	finish := func() TransferResult {
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

	sessionState, err := parseType5SessionBlob(manualResult.SessionBlob)
	if err != nil {
		return finish(), err
	}
	sessionBase := buildSessionBaseRequest(uint32(sessionState.UIN))

	innerBody, err := buildConfiguredTransferInnerBody(
		input,
		innerMode,
		sessionBase,
		appID,
		hostAppID,
	)
	if err != nil {
		return finish(), err
	}

	request, err := buildPackedTransferRequest(transferEnvelopeSpec{
		CGI:          cgi,
		TargetAppID:  appID,
		HostAppID:    hostAppID,
		Route:        input.Route,
		InnerBody:    innerBody,
		OuterField4:  outerField4,
		OuterField8:  outerField8,
		Plugin:       plugin,
		OuterField10: outerField10,
	}, sessionBase, sessionState, taskID, taskType)
	if err != nil {
		return finish(), err
	}

	result.Request = TransferRequestTrace{
		CGI:             cgi,
		Route:           input.Route,
		Sequence:        sequence,
		TaskID:          request.TaskID,
		TaskType:        request.TaskType,
		IdentityMode:    identityMode,
		InnerMode:       string(innerMode),
		InnerBodyLen:    len(innerBody),
		HostAppID:       hostAppID,
		OuterField4:     outerField4,
		OuterField8:     outerField8,
		Plugin:          plugin,
		OuterField10:    outerField10,
		WrapperLen:      len(request.Wrapper),
		OutBodyLen:      len(request.OutBody),
		PackRoundTripOK: request.ReplayDecryptsToWrapper,
	}

	stage, err := longlink.SendPackedBody(ctx, PackedStage{
		Profile:      request.Profile,
		IdentityMode: identityMode,
		Body:         request.OutBody,
		Seq:          sequence,
		TaskID:       request.TaskID,
		TaskType:     request.TaskType,
		Timeout:      e.timeout,
	})
	if err != nil {
		return finish(), err
	}

	decoded, err := decodeTransferStage(stage, request, responseMode)
	if err != nil {
		return finish(), err
	}
	result.OK = true
	result.Response = decoded.Trace
	result.Decoded = decoded.Decoded
	result.DecodedFormat = decoded.Format
	result.DecodedRaw = decoded.DecodedRaw
	result.Plain = decoded.Plain
	return finish(), nil
}

func validateTransferCGI(cgi string) error {
	if cgi == "" {
		return fmt.Errorf("cgi is required")
	}
	if len(cgi) > 2048 {
		return fmt.Errorf("cgi must not exceed 2048 characters")
	}
	if !strings.HasPrefix(cgi, "/") {
		return fmt.Errorf("cgi must start with /")
	}
	parsed, err := url.Parse(cgi)
	if err != nil {
		return fmt.Errorf("invalid cgi: %w", err)
	}
	if parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("cgi must be a relative path without scheme, host, userinfo or fragment")
	}
	return nil
}

func buildConfiguredTransferInnerBody(
	input TransferInput,
	mode TransferInnerMode,
	sessionBase []byte,
	targetAppID string,
	hostAppID string,
) ([]byte, error) {
	switch mode {
	case TransferInnerStandard:
		if len(input.InnerFields) != 0 || input.RawInnerBodySet {
			return nil, fmt.Errorf("standard inner mode does not accept inner fields or raw inner body")
		}
		body := []byte{}
		body = append(body, pbFieldBytes(1, sessionBase)...)
		body = append(body, pbFieldBytes(2, []byte(targetAppID))...)
		if input.HasData {
			body = append(body, pbFieldBytes(3, input.Data)...)
		}
		return body, nil
	case TransferInnerRaw:
		if !input.RawInnerBodySet {
			return nil, fmt.Errorf("raw inner mode requires inner_base64")
		}
		if len(input.InnerFields) != 0 || input.HasData {
			return nil, fmt.Errorf("raw inner mode does not accept inner fields or data")
		}
		return append([]byte{}, input.RawInnerBody...), nil
	case TransferInnerProtobuf:
		if len(input.InnerFields) == 0 {
			return nil, fmt.Errorf("protobuf inner mode requires at least one inner field")
		}
		if input.RawInnerBodySet || input.HasData {
			return nil, fmt.Errorf("protobuf inner mode does not accept raw inner body or data")
		}
		if len(input.InnerFields) > 256 {
			return nil, fmt.Errorf("protobuf inner mode supports at most 256 fields")
		}
		body := make([]byte, 0, 256)
		for index, field := range input.InnerFields {
			encoded, err := encodeTransferProtoField(field, sessionBase, targetAppID, hostAppID)
			if err != nil {
				return nil, fmt.Errorf("inner_fields[%d]: %w", index, err)
			}
			body = append(body, encoded...)
			if len(body) > transferInnerBodyLimit {
				return nil, fmt.Errorf("encoded protobuf inner body exceeds 8 MiB")
			}
		}
		return body, nil
	default:
		return nil, fmt.Errorf("unsupported inner mode %q", mode)
	}
}

func encodeTransferProtoField(
	field TransferProtoField,
	sessionBase []byte,
	targetAppID string,
	hostAppID string,
) ([]byte, error) {
	if field.Number == 0 || field.Number > 536870911 {
		return nil, fmt.Errorf("field number must be between 1 and 536870911")
	}
	if field.Number >= 19000 && field.Number <= 19999 {
		return nil, fmt.Errorf("field number %d is reserved by protobuf", field.Number)
	}
	number := int(field.Number)
	switch field.Kind {
	case TransferProtoSessionBase:
		return pbFieldBytes(number, sessionBase), nil
	case TransferProtoTargetAppID:
		return pbFieldBytes(number, []byte(targetAppID)), nil
	case TransferProtoHostAppID:
		return pbFieldBytes(number, []byte(hostAppID)), nil
	case TransferProtoIlinkAppID:
		return pbFieldBytes(number, []byte(IlinkAppID)), nil
	case TransferProtoString:
		return pbFieldBytes(number, []byte(field.Text)), nil
	case TransferProtoBytes:
		return pbFieldBytes(number, field.Bytes), nil
	case TransferProtoVarint:
		return pbFieldVarint(number, field.Uint), nil
	case TransferProtoFixed32:
		if field.Uint > uint64(^uint32(0)) {
			return nil, fmt.Errorf("fixed32 value exceeds uint32")
		}
		return pbFieldFixed32(number, uint32(field.Uint)), nil
	case TransferProtoFixed64:
		return pbFieldFixed64(number, field.Uint), nil
	default:
		return nil, fmt.Errorf("unsupported field type %q", field.Kind)
	}
}

func buildTransferWrapper(spec transferEnvelopeSpec, sessionBase []byte) []byte {
	wrapper := []byte{}
	wrapper = append(wrapper, pbFieldBytes(1, sessionBase)...)
	wrapper = append(wrapper, pbFieldBytes(2, []byte(spec.CGI))...)
	wrapper = append(wrapper, pbFieldBytes(3, []byte(spec.HostAppID))...)
	wrapper = append(wrapper, pbFieldVarint(4, spec.OuterField4)...)
	wrapper = append(wrapper, pbFieldBytes(5, spec.InnerBody)...)
	wrapper = append(wrapper, pbFieldBytes(6, []byte(spec.TargetAppID))...)
	wrapper = append(wrapper, pbFieldVarint(7, uint64(spec.Route))...)
	wrapper = append(wrapper, pbFieldVarint(8, spec.OuterField8)...)
	wrapper = append(wrapper, pbFieldBytes(9, []byte(spec.Plugin))...)
	wrapper = append(wrapper, pbFieldVarint(10, spec.OuterField10)...)
	return wrapper
}

func buildPackedTransferRequest(
	spec transferEnvelopeSpec,
	sessionBase []byte,
	sessionState Type5Session,
	taskID uint32,
	taskType int32,
) (transferPackedRequest, error) {
	wrapper := buildTransferWrapper(spec, sessionBase)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return transferPackedRequest{}, fmt.Errorf("generate transfer nonce: %w", err)
	}

	outBody, replayOK, err := packOperateWXDataWrapper(wrapper, sessionState.PackRequestAESKey, nonce)
	if err != nil {
		return transferPackedRequest{}, err
	}

	return transferPackedRequest{
		Wrapper:                 wrapper,
		OutBody:                 outBody,
		Profile:                 profileFromType5Session(sessionState),
		AESKey:                  append([]byte{}, sessionState.PackRequestAESKey...),
		ResponseAESKey:          append([]byte{}, sessionState.ResponseAESKey...),
		ResponseAESKeyAlt:       append([]byte{}, sessionState.ResponseAESKeyAlt...),
		ReplayDecryptsToWrapper: replayOK,
		TaskID:                  taskID,
		TaskType:                taskType,
	}, nil
}

func decodeTransferStage(
	stage StageResult,
	request transferPackedRequest,
	responseMode TransferResponseMode,
) (transferDecodedResponse, error) {
	bodies := responseBodiesFromStage(stage)
	if len(bodies) == 0 {
		return transferDecodedResponse{}, fmt.Errorf("transfer response missing")
	}

	decryptKeys := []struct {
		label string
		key   []byte
	}{
		{label: "raw89-sessionField2", key: request.ResponseAESKey},
		{label: "raw89-sessionField3", key: request.ResponseAESKeyAlt},
		{label: "raw89-packrequest", key: request.AESKey},
	}

	var firstDecryptErr error
	for _, body := range bodies {
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
			format, decodedRaw, decoded, decodeErr := decodeTransferPlain(plain, responseMode)
			if decodeErr != nil {
				return transferDecodedResponse{}, decodeErr
			}
			return transferDecodedResponse{
				Trace: TransferResponseTrace{
					Source: body.Source, Sequence: stage.Seq, TaskID: stage.TaskID,
					TaskType: stage.TaskType, Tag4: body.Tag4, Tag23: body.Tag23,
					BodyLen: len(body.Body), DecodeMode: row.label, PlainLen: len(plain),
				},
				Decoded: decoded, Format: format, DecodedRaw: decodedRaw, Plain: plain,
			}, nil
		}

		directJSON, _ := extractTransferJSON(body.Body)
		_, directProtoErr := decodeTransferProtobuf(body.Body)
		if directJSON != "" || directProtoErr == nil {
			format, decodedRaw, decoded, err := decodeTransferPlain(body.Body, responseMode)
			if err != nil {
				return transferDecodedResponse{}, err
			}
			return transferDecodedResponse{
				Trace: TransferResponseTrace{
					Source: body.Source, Sequence: stage.Seq, TaskID: stage.TaskID,
					TaskType: stage.TaskType, Tag4: body.Tag4, Tag23: body.Tag23,
					BodyLen: len(body.Body), DecodeMode: "direct-proto", PlainLen: len(body.Body),
				},
				Decoded: decoded, Format: format, DecodedRaw: decodedRaw, Plain: body.Body,
			}, nil
		}
	}

	if firstDecryptErr != nil {
		return transferDecodedResponse{}, fmt.Errorf("decode transfer response: %w", firstDecryptErr)
	}
	return transferDecodedResponse{}, fmt.Errorf("transfer response body empty")
}

func decodeTransferPlain(
	plain []byte,
	mode TransferResponseMode,
) (string, string, any, error) {
	switch mode {
	case TransferResponseRaw:
		return "raw", "", nil, nil
	case TransferResponseJSON:
		decodedRaw, decoded := extractTransferJSON(plain)
		if decodedRaw == "" {
			return "", "", nil, fmt.Errorf("transfer response does not contain JSON")
		}
		return "json", decodedRaw, decoded, nil
	case TransferResponseProtobuf:
		decoded, err := decodeTransferProtobuf(plain)
		if err != nil {
			return "", "", nil, fmt.Errorf("decode transfer protobuf response: %w", err)
		}
		return "protobuf", "", decoded, nil
	case TransferResponseAuto:
		if decodedRaw, decoded := extractTransferJSON(plain); decodedRaw != "" {
			return "json", decodedRaw, decoded, nil
		}
		if decoded, err := decodeTransferProtobuf(plain); err == nil {
			return "protobuf", "", decoded, nil
		}
		return "raw", "", nil, nil
	default:
		return "", "", nil, fmt.Errorf("unsupported transfer response mode %q", mode)
	}
}

func decodeTransferProtobuf(raw []byte) (TransferProtoDecoded, error) {
	fields, stringsFound, err := decodeTransferProtoFields(raw, 0)
	if err != nil {
		return TransferProtoDecoded{}, err
	}
	if len(fields) == 0 {
		return TransferProtoDecoded{}, fmt.Errorf("protobuf response has no fields")
	}
	stringsFound = uniqueSortedTransferStrings(stringsFound)
	codes := make([]string, 0)
	for _, value := range stringsFound {
		if jsLoginCodeRE.MatchString(value) {
			codes = append(codes, value)
		}
	}
	return TransferProtoDecoded{
		Format: "protobuf", Fields: fields,
		Strings: stringsFound, CodeCandidates: codes,
	}, nil
}

func decodeTransferProtoFields(
	raw []byte,
	depth int,
) ([]TransferProtoDecodedField, []string, error) {
	if depth > 8 {
		return nil, nil, fmt.Errorf("protobuf nesting exceeds 8 levels")
	}
	fields := make([]TransferProtoDecodedField, 0)
	stringsFound := make([]string, 0)
	for offset := 0; offset < len(raw); {
		tag, next, err := readVarint(raw, offset)
		if err != nil {
			return nil, nil, err
		}
		offset = next
		number := uint32(tag >> 3)
		wire := int(tag & 7)
		if number == 0 || number > 536870911 {
			return nil, nil, fmt.Errorf("invalid protobuf field number %d", number)
		}
		field := TransferProtoDecodedField{Number: number}
		switch wire {
		case 0:
			value, cursor, err := readVarint(raw, offset)
			if err != nil {
				return nil, nil, err
			}
			offset = cursor
			field.Wire = "varint"
			field.Varint = &value
		case 1:
			if offset+8 > len(raw) {
				return nil, nil, fmt.Errorf("fixed64 field %d truncated", number)
			}
			value := binary.LittleEndian.Uint64(raw[offset : offset+8])
			offset += 8
			field.Wire = "fixed64"
			field.Fixed64 = &value
		case 2:
			length, cursor, err := readVarint(raw, offset)
			if err != nil {
				return nil, nil, err
			}
			offset = cursor
			if length > uint64(len(raw)-offset) {
				return nil, nil, fmt.Errorf("bytes field %d truncated", number)
			}
			end := offset + int(length)
			value := append([]byte{}, raw[offset:end]...)
			offset = end
			field.Wire = "bytes"
			field.Base64 = base64.StdEncoding.EncodeToString(value)
			if text, ok := transferPrintableText(value); ok {
				field.Text = text
				stringsFound = append(stringsFound, text)
			}
			if len(value) > 0 && depth < 8 {
				nested, nestedStrings, nestedErr := decodeTransferProtoFields(value, depth+1)
				if nestedErr == nil && len(nested) > 0 {
					field.Nested = nested
					stringsFound = append(stringsFound, nestedStrings...)
				}
			}
		case 5:
			if offset+4 > len(raw) {
				return nil, nil, fmt.Errorf("fixed32 field %d truncated", number)
			}
			value := binary.LittleEndian.Uint32(raw[offset : offset+4])
			offset += 4
			field.Wire = "fixed32"
			field.Fixed32 = &value
		default:
			return nil, nil, fmt.Errorf("unsupported protobuf wire type %d", wire)
		}
		fields = append(fields, field)
	}
	return fields, stringsFound, nil
}

func transferPrintableText(raw []byte) (string, bool) {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return "", false
	}
	text := string(raw)
	printable := 0
	total := 0
	for _, current := range text {
		total++
		if current == '\t' || current == '\n' || current == '\r' || current >= 32 {
			printable++
		}
	}
	if total == 0 || float64(printable)/float64(total) < 0.85 {
		return "", false
	}
	return text, true
}

func uniqueSortedTransferStrings(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(unique))
	for value := range unique {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func extractTransferJSON(raw []byte) (string, any) {
	if text, value, ok := decodeTransferCompleteJSON(raw); ok {
		return text, value
	}
	for _, text := range collectProtoStrings(raw, 0) {
		if decodedRaw, value, ok := decodeTransferCompleteJSON([]byte(text)); ok {
			return decodedRaw, value
		}
		if decodedRaw, value, ok := decodeTransferEmbeddedJSON([]byte(text)); ok {
			return decodedRaw, value
		}
	}
	if text, value, ok := decodeTransferEmbeddedJSON(raw); ok {
		return text, value
	}
	return "", nil
}

func decodeTransferCompleteJSON(raw []byte) (string, any, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", nil, false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", nil, false
	}
	return string(trimmed), value, true
}

func decodeTransferEmbeddedJSON(raw []byte) (string, any, bool) {
	for index, current := range raw {
		if current != '{' && current != '[' {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(raw[index:]))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			continue
		}
		return string(encoded), value, true
	}
	return "", nil, false
}
