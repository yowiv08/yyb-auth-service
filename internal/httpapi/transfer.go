package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/service"
)

const httpDefaultTransferRoute uint32 = 1029

type transferRequest struct {
	UnionID      string                    `json:"unionid"`
	AppID        string                    `json:"appid"`
	CGI          string                    `json:"cgi"`
	Route        *uint32                   `json:"route"`
	DataFormat   string                    `json:"data_format"`
	Data         json.RawMessage           `json:"data"`
	InnerMode    string                    `json:"inner_mode"`
	InnerFields  []transferProtoFieldInput `json:"inner_fields"`
	InnerBase64  *string                   `json:"inner_base64"`
	Outer        *transferOuterInput       `json:"outer"`
	Transport    *transferTransportInput   `json:"transport"`
	ResponseMode string                    `json:"response_mode"`
}

type transferProtoFieldInput struct {
	Number uint32  `json:"number"`
	Type   string  `json:"type"`
	Value  *string `json:"value"`
	Uint   *uint64 `json:"uint"`
}

type transferOuterInput struct {
	HostAppID string  `json:"host_appid"`
	Field4    *uint64 `json:"field4"`
	Field8    *uint64 `json:"field8"`
	Plugin    *string `json:"plugin"`
	Field10   *uint64 `json:"field10"`
}

type transferTransportInput struct {
	Sequence     *uint64 `json:"sequence"`
	TaskID       *uint32 `json:"task_id"`
	TaskType     *int32  `json:"task_type"`
	IdentityMode string  `json:"identity_mode"`
}

type transferResponse struct {
	OK            bool                         `json:"ok"`
	UnionID       string                       `json:"unionid"`
	AppID         string                       `json:"appid"`
	CGI           string                       `json:"cgi"`
	Route         uint32                       `json:"route"`
	DataFormat    string                       `json:"data_format,omitempty"`
	InnerMode     string                       `json:"inner_mode"`
	ResponseMode  string                       `json:"response_mode"`
	Decoded       any                          `json:"decoded"`
	DecodedFormat string                       `json:"decoded_format"`
	DecodedRaw    string                       `json:"decoded_raw"`
	PlainB64      string                       `json:"plain_base64"`
	Request       native.TransferRequestTrace  `json:"request"`
	Response      native.TransferResponseTrace `json:"response"`
	Duration      string                       `json:"duration"`
}

func (s *Server) handleTransfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	startedAt := time.Now()

	var body transferRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	unionID, err := requiredString(body.UnionID, "unionid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	appID, err := requiredString(body.AppID, "appid")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cgi := strings.TrimSpace(body.CGI)
	if err := validateTransferCGI(cgi); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	route := httpDefaultTransferRoute
	if body.Route != nil {
		route = *body.Route
	}
	if route == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("route 必须大于 0"))
		return
	}

	input, format, innerMode, responseMode, err := prepareNativeTransferInput(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	input.AppID = appID
	input.CGI = cgi
	input.Route = route

	result, err := s.cloudService.Transfer(r.Context(), unionID, input)
	if err != nil {
		writeTransferError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, transferResponse{
		OK:            result.OK,
		UnionID:       unionID,
		AppID:         result.AppID,
		CGI:           result.CGI,
		Route:         result.Route,
		DataFormat:    string(format),
		InnerMode:     string(innerMode),
		ResponseMode:  string(responseMode),
		Decoded:       result.Decoded,
		DecodedFormat: result.DecodedFormat,
		DecodedRaw:    result.DecodedRaw,
		PlainB64:      base64.StdEncoding.EncodeToString(result.Plain),
		Request:       result.Request,
		Response:      result.Response,
		Duration:      formatDurationHMS(time.Since(startedAt)),
	})
}

func writeTransferError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrTransferAccountNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, err)
	default:
		writeError(w, http.StatusBadGateway, err)
	}
}

func prepareNativeTransferInput(
	input transferRequest,
) (native.TransferInput, native.TransferDataFormat, native.TransferInnerMode, native.TransferResponseMode, error) {
	innerMode := native.TransferInnerMode(strings.TrimSpace(input.InnerMode))
	if innerMode == "" {
		innerMode = native.TransferInnerStandard
	}
	responseMode := native.TransferResponseMode(strings.TrimSpace(input.ResponseMode))
	if responseMode == "" {
		responseMode = native.TransferResponseAuto
	}
	switch responseMode {
	case native.TransferResponseAuto, native.TransferResponseJSON,
		native.TransferResponseProtobuf, native.TransferResponseRaw:
	default:
		return native.TransferInput{}, "", "", "", fmt.Errorf(
			"response_mode 必须是 auto、json、protobuf 或 raw",
		)
	}

	result := native.TransferInput{InnerMode: innerMode, ResponseMode: responseMode}
	format := native.TransferDataFormat("")
	switch innerMode {
	case native.TransferInnerStandard:
		if len(input.InnerFields) != 0 || input.InnerBase64 != nil {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"standard inner_mode 不接受 inner_fields 或 inner_base64",
			)
		}
		formatRaw := strings.TrimSpace(input.DataFormat)
		if formatRaw == "" {
			formatRaw = string(native.TransferDataNone)
		}
		var err error
		format, result.Data, result.HasData, err = prepareTransferData(formatRaw, input.Data)
		if err != nil {
			return native.TransferInput{}, "", "", "", err
		}
	case native.TransferInnerProtobuf:
		if err := requireNoStandardTransferData(input.DataFormat, input.Data); err != nil {
			return native.TransferInput{}, "", "", "", err
		}
		if input.InnerBase64 != nil {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"protobuf inner_mode 不接受 inner_base64",
			)
		}
		fields, err := prepareTransferProtoFields(input.InnerFields)
		if err != nil {
			return native.TransferInput{}, "", "", "", err
		}
		result.InnerFields = fields
	case native.TransferInnerRaw:
		if err := requireNoStandardTransferData(input.DataFormat, input.Data); err != nil {
			return native.TransferInput{}, "", "", "", err
		}
		if len(input.InnerFields) != 0 {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"raw inner_mode 不接受 inner_fields",
			)
		}
		if input.InnerBase64 == nil {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"raw inner_mode 需要 inner_base64",
			)
		}
		decoded, err := base64.StdEncoding.DecodeString(*input.InnerBase64)
		if err != nil {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"inner_base64 必须是标准 base64: %w", err,
			)
		}
		result.RawInnerBody = decoded
		result.RawInnerBodySet = true
	default:
		return native.TransferInput{}, "", "", "", fmt.Errorf(
			"inner_mode 必须是 standard、protobuf 或 raw",
		)
	}

	if input.Outer != nil {
		hostAppID := strings.TrimSpace(input.Outer.HostAppID)
		if len(hostAppID) > 128 {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"outer.host_appid 不能超过 128 个字符",
			)
		}
		if input.Outer.Plugin != nil && len(*input.Outer.Plugin) > 256 {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"outer.plugin 不能超过 256 个字符",
			)
		}
		result.Outer = native.TransferOuterOptions{
			HostAppID: hostAppID,
			Field4:    input.Outer.Field4,
			Field8:    input.Outer.Field8,
			Plugin:    input.Outer.Plugin,
			Field10:   input.Outer.Field10,
		}
	}
	if input.Transport != nil {
		if input.Transport.Sequence != nil && *input.Transport.Sequence == 0 {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"transport.sequence 必须大于 0",
			)
		}
		if input.Transport.TaskID != nil && *input.Transport.TaskID == 0 {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"transport.task_id 必须大于 0",
			)
		}
		identityMode := strings.TrimSpace(input.Transport.IdentityMode)
		if identityMode != "" && identityMode != "account" && identityMode != "zero" {
			return native.TransferInput{}, "", "", "", fmt.Errorf(
				"transport.identity_mode 必须是 account 或 zero",
			)
		}
		if input.Transport.Sequence != nil {
			result.Transport.Sequence = *input.Transport.Sequence
		}
		if input.Transport.TaskID != nil {
			result.Transport.TaskID = *input.Transport.TaskID
		}
		result.Transport.TaskType = input.Transport.TaskType
		result.Transport.IdentityMode = identityMode
	}
	return result, format, innerMode, responseMode, nil
}

func requireNoStandardTransferData(format string, raw json.RawMessage) error {
	format = strings.TrimSpace(format)
	if format != "" && format != string(native.TransferDataNone) {
		return fmt.Errorf("自定义 inner_mode 下必须省略 data_format")
	}
	if len(raw) != 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("自定义 inner_mode 下 data 必须省略或为 null")
	}
	return nil
}

func prepareTransferProtoFields(
	fields []transferProtoFieldInput,
) ([]native.TransferProtoField, error) {
	if len(fields) == 0 {
		return nil, fmt.Errorf("protobuf inner_mode 需要 inner_fields")
	}
	if len(fields) > 256 {
		return nil, fmt.Errorf("inner_fields 最多 256 个字段")
	}
	result := make([]native.TransferProtoField, 0, len(fields))
	for index, field := range fields {
		if field.Number == 0 || field.Number > 536870911 {
			return nil, fmt.Errorf(
				"inner_fields[%d].number 必须在 1 到 536870911 之间", index,
			)
		}
		if field.Number >= 19000 && field.Number <= 19999 {
			return nil, fmt.Errorf(
				"inner_fields[%d].number 属于 protobuf 保留段", index,
			)
		}
		kind := native.TransferProtoFieldKind(strings.TrimSpace(field.Type))
		prepared := native.TransferProtoField{Number: field.Number, Kind: kind}
		switch kind {
		case native.TransferProtoSessionBase, native.TransferProtoTargetAppID,
			native.TransferProtoHostAppID, native.TransferProtoIlinkAppID:
			if field.Value != nil || field.Uint != nil {
				return nil, fmt.Errorf(
					"inner_fields[%d] 模板类型不接受 value 或 uint", index,
				)
			}
		case native.TransferProtoString:
			if field.Value == nil || field.Uint != nil {
				return nil, fmt.Errorf(
					"inner_fields[%d] string 类型需要 value 且不接受 uint", index,
				)
			}
			prepared.Text = *field.Value
		case native.TransferProtoBytes:
			if field.Value == nil || field.Uint != nil {
				return nil, fmt.Errorf(
					"inner_fields[%d] bytes 类型需要 base64 value 且不接受 uint", index,
				)
			}
			decoded, err := base64.StdEncoding.DecodeString(*field.Value)
			if err != nil {
				return nil, fmt.Errorf(
					"inner_fields[%d].value 必须是标准 base64: %w", index, err,
				)
			}
			prepared.Bytes = decoded
		case native.TransferProtoVarint, native.TransferProtoFixed32, native.TransferProtoFixed64:
			if field.Uint == nil || field.Value != nil {
				return nil, fmt.Errorf(
					"inner_fields[%d] 数值类型需要 uint 且不接受 value", index,
				)
			}
			if kind == native.TransferProtoFixed32 && *field.Uint > uint64(^uint32(0)) {
				return nil, fmt.Errorf("inner_fields[%d].uint 超出 fixed32 范围", index)
			}
			prepared.Uint = *field.Uint
		default:
			return nil, fmt.Errorf(
				"inner_fields[%d].type 必须是 session_base、target_appid、host_appid、ilink_appid、string、bytes、varint、fixed32 或 fixed64",
				index,
			)
		}
		result = append(result, prepared)
	}
	return result, nil
}

func prepareTransferData(
	formatRaw string,
	raw json.RawMessage,
) (native.TransferDataFormat, []byte, bool, error) {
	format := native.TransferDataFormat(strings.TrimSpace(formatRaw))
	switch format {
	case native.TransferDataNone:
		if len(raw) != 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return "", nil, false, fmt.Errorf("data_format 为 none 时 data 必须省略或为 null")
		}
		return format, nil, false, nil
	case native.TransferDataJSON:
		if len(raw) == 0 {
			return "", nil, false, fmt.Errorf("data_format 为 json 时 data 必填")
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return "", nil, false, fmt.Errorf("data 必须是合法 JSON: %w", err)
		}
		return format, compact.Bytes(), true, nil
	case native.TransferDataText:
		if len(raw) == 0 {
			return "", nil, false, fmt.Errorf("data_format 为 text 时 data 必填")
		}
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return "", nil, false, fmt.Errorf("data_format 为 text 时 data 必须是 JSON 字符串")
		}
		return format, []byte(text), true, nil
	case native.TransferDataBase64:
		if len(raw) == 0 {
			return "", nil, false, fmt.Errorf("data_format 为 base64 时 data 必填")
		}
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return "", nil, false, fmt.Errorf("data_format 为 base64 时 data 必须是 JSON 字符串")
		}
		decoded, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return "", nil, false, fmt.Errorf("data 必须是标准 base64: %w", err)
		}
		return format, decoded, true, nil
	default:
		return "", nil, false, fmt.Errorf("data_format 必须是 none、json、text 或 base64")
	}
}

func validateTransferCGI(cgi string) error {
	if cgi == "" {
		return fmt.Errorf("cgi 必填")
	}
	if len(cgi) > 2048 {
		return fmt.Errorf("cgi 不能超过 2048 个字符")
	}
	if !strings.HasPrefix(cgi, "/") {
		return fmt.Errorf("cgi 必须以 / 开头")
	}
	parsed, err := url.Parse(cgi)
	if err != nil {
		return fmt.Errorf("cgi 非法: %w", err)
	}
	if parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("cgi 必须是相对路径，不能带 scheme、host、userinfo 或 fragment")
	}
	return nil
}
