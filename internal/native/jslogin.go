package native

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"regexp"
	"sort"
	"unicode/utf8"
)

const (
	JSLoginTaskID        = 2881
	JSLoginTaskType      = 2
	jsLoginCGI           = "/cgi-bin/mmbiz-bin/js-login"
	defaultHostAppID     = "wxd44977328b36e647"
	defaultDeviceMAC     = "00-E2-69-69-87-78"
	defaultClientVersion = 1661404927
	defaultPlatform      = "Windows"
	defaultPlugin        = "WindowsxWebPlugin"
	defaultOuterField4   = 5
	defaultRouteCode     = 1029
	defaultOuterField8   = 0x60003951
	defaultOuterField10  = 0x22313951
)

var jsLoginCodeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

type JSLoginRequest struct {
	AppID                   string
	Wrapper                 []byte
	OutBody                 []byte
	Compressed              []byte
	Nonce                   []byte
	Profile                 LonglinkProfile
	AESKey                  []byte
	ResponseAESKey          []byte
	ResponseAESKeyAlt       []byte
	ReplayDecryptsToWrapper bool
	TaskID                  uint32
	TaskType                int32
}

type JSLoginAttempt struct {
	Source     string `json:"source"`
	BodyLen    int    `json:"body_len"`
	DecodeMode string `json:"decode_mode,omitempty"`
	OK         bool   `json:"ok"`
	Code       string `json:"code,omitempty"`
	Ret        int64  `json:"ret,omitempty"`
	ErrMsg     string `json:"errmsg,omitempty"`
	Error      string `json:"error,omitempty"`
	Tag4       int64  `json:"tag4,omitempty"`
	Tag23      int64  `json:"tag23,omitempty"`
}

type JSLoginDecoded struct {
	OK             bool             `json:"ok"`
	Code           string           `json:"code,omitempty"`
	Ret            int64            `json:"ret,omitempty"`
	ErrMsg         string           `json:"errmsg,omitempty"`
	DecodeMode     string           `json:"decode_mode,omitempty"`
	CodeCandidates []string         `json:"code_candidates,omitempty"`
	Attempts       []JSLoginAttempt `json:"attempts,omitempty"`
}

type jsLoginBodyCandidate struct {
	Source string
	Body   []byte
	Tag4   int64
	Tag23  int64
}

func buildJsLoginRequest(
	appID string,
	sessionBlob []byte,
	taskID uint32,
	taskType int32,
) (JSLoginRequest, error) {
	targetAppID := firstNonEmpty(appID)
	if targetAppID == "" {
		return JSLoginRequest{}, fmt.Errorf("appid required")
	}

	sessionState, err := parseType5SessionBlob(sessionBlob)
	if err != nil {
		return JSLoginRequest{}, err
	}

	wrapper := buildJsLoginWrapper(targetAppID, uint32(sessionState.UIN))
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return JSLoginRequest{}, fmt.Errorf("generate jslogin nonce: %w", err)
	}

	compressed := lz4CompressBlock(wrapper)
	outBody, err := aesGCMEncrypt192Packed(sessionState.PackRequestAESKey, compressed, nonce, nil)
	if err != nil {
		return JSLoginRequest{}, err
	}

	replayDecryptsToWrapper := false
	if replayCompressed, err := aesGCMDecrypt192Packed(sessionState.PackRequestAESKey, outBody, nil); err == nil {
		if replayRaw, err := lz4DecompressBlock(replayCompressed); err == nil {
			replayDecryptsToWrapper = bytes.Equal(replayRaw, wrapper)
		}
	}

	return JSLoginRequest{
		AppID:                   targetAppID,
		Wrapper:                 wrapper,
		OutBody:                 outBody,
		Compressed:              compressed,
		Nonce:                   nonce,
		Profile:                 profileFromType5Session(sessionState),
		AESKey:                  append([]byte{}, sessionState.PackRequestAESKey...),
		ResponseAESKey:          append([]byte{}, sessionState.ResponseAESKey...),
		ResponseAESKeyAlt:       append([]byte{}, sessionState.ResponseAESKeyAlt...),
		ReplayDecryptsToWrapper: replayDecryptsToWrapper,
		TaskID:                  taskID,
		TaskType:                taskType,
	}, nil
}

func profileFromType5Session(sessionState Type5Session) LonglinkProfile {
	return LonglinkProfile{
		UIN:        sessionState.UIN,
		IlinkAppID: IlinkAppID,
		Field27:    append([]byte{}, sessionState.Field27...),
	}
}

func buildJsLoginWrapper(targetAppID string, sessionDynamicField2 uint32) []byte {
	sessionBase := buildSessionBaseRequest(sessionDynamicField2)
	innerBody := buildJsLoginInnerBody(targetAppID, sessionBase)

	wrapper := []byte{}
	wrapper = append(wrapper, pbFieldBytes(1, sessionBase)...)
	wrapper = append(wrapper, pbFieldBytes(2, []byte(jsLoginCGI))...)
	wrapper = append(wrapper, pbFieldBytes(3, []byte(defaultHostAppID))...)
	wrapper = append(wrapper, pbFieldVarint(4, defaultOuterField4)...)
	wrapper = append(wrapper, pbFieldBytes(5, innerBody)...)
	wrapper = append(wrapper, pbFieldBytes(6, []byte(targetAppID))...)
	wrapper = append(wrapper, pbFieldVarint(7, defaultRouteCode)...)
	wrapper = append(wrapper, pbFieldVarint(8, defaultOuterField8)...)
	wrapper = append(wrapper, pbFieldBytes(9, []byte(defaultPlugin))...)
	wrapper = append(wrapper, pbFieldVarint(10, defaultOuterField10)...)
	return wrapper
}

func buildSessionBaseRequest(sessionDynamicField2 uint32) []byte {
	body := []byte{}
	body = append(body, pbFieldBytes(1, []byte("sessionkey"))...)
	body = append(body, pbFieldVarint(2, uint64(sessionDynamicField2))...)
	body = append(body, pbFieldBytes(3, []byte(defaultDeviceMAC))...)
	body = append(body, pbFieldVarint(4, defaultClientVersion)...)
	body = append(body, pbFieldBytes(5, []byte(defaultPlatform))...)
	body = append(body, pbFieldVarint(6, 0)...)
	return body
}

func buildJsLoginInnerBody(targetAppID string, sessionBase []byte) []byte {
	body := []byte{}
	body = append(body, pbFieldBytes(1, sessionBase)...)
	body = append(body, pbFieldBytes(2, []byte(targetAppID))...)
	body = append(body, pbFieldVarint(4, 1)...)
	body = append(body, pbFieldBytes(5, []byte{})...)
	body = append(body, pbFieldBytes(6, []byte{})...)
	body = append(body, pbFieldVarint(7, 1)...)
	return body
}

func decodeJsLoginStage(
	stage StageResult,
	request JSLoginRequest,
	sessionKey []byte,
) JSLoginDecoded {
	bodies := responseBodiesFromStage(stage)
	attempts := make([]JSLoginAttempt, 0, len(bodies)*5)
	decryptKeys := []struct {
		label string
		key   []byte
	}{
		{label: "raw89-sessionField2", key: request.ResponseAESKey},
		{label: "raw89-sessionField3", key: request.ResponseAESKeyAlt},
		{label: "raw89-packrequest", key: request.AESKey},
	}

	if len(sessionKey) >= 24 {
		decryptKeys = append(decryptKeys, struct {
			label string
			key   []byte
		}{label: "raw89-sessionKey24", key: append([]byte{}, sessionKey[:24]...)})
	}
	if len(sessionKey) >= 16 {
		decryptKeys = append(decryptKeys, struct {
			label string
			key   []byte
		}{label: "raw89-sessionKey16", key: append([]byte{}, sessionKey[:16]...)})
	}

	for _, body := range bodies {
		if len(body.Body) == 0 {
			attempts = append(attempts, JSLoginAttempt{
				Source:  body.Source,
				BodyLen: 0,
				OK:      false,
				Error:   "response body empty",
				Tag4:    body.Tag4,
				Tag23:   body.Tag23,
			})
			continue
		}

		for _, key := range decryptKeys {
			if len(key.key) == 0 {
				continue
			}
			decoded, err := decodeRaw89(body.Body, key.key)
			if err != nil {
				attempts = append(attempts, JSLoginAttempt{
					Source:     body.Source,
					BodyLen:    len(body.Body),
					DecodeMode: key.label,
					OK:         false,
					Error:      err.Error(),
					Tag4:       body.Tag4,
					Tag23:      body.Tag23,
				})
				continue
			}

			attempts = append(attempts, JSLoginAttempt{
				Source:     body.Source,
				BodyLen:    len(body.Body),
				DecodeMode: key.label,
				OK:         decoded.OK,
				Code:       decoded.Code,
				Ret:        decoded.Ret,
				ErrMsg:     decoded.ErrMsg,
				Tag4:       body.Tag4,
				Tag23:      body.Tag23,
			})
			if decoded.OK {
				decoded.DecodeMode = key.label
				decoded.Attempts = attempts
				return decoded
			}
		}

		decoded := decodeJsLoginResponse(body.Body)
		attempts = append(attempts, JSLoginAttempt{
			Source:     body.Source,
			BodyLen:    len(body.Body),
			DecodeMode: "direct-proto",
			OK:         decoded.OK,
			Code:       decoded.Code,
			Ret:        decoded.Ret,
			ErrMsg:     decoded.ErrMsg,
			Tag4:       body.Tag4,
			Tag23:      body.Tag23,
		})
		if decoded.OK {
			decoded.DecodeMode = "direct-proto"
			decoded.Attempts = attempts
			return decoded
		}
	}

	ret, errMsg := summarizeJSLoginBusinessError(attempts)
	return JSLoginDecoded{OK: false, Ret: ret, ErrMsg: errMsg, Attempts: attempts}
}

func summarizeJSLoginFailure(attempts []JSLoginAttempt) string {
	if len(attempts) == 0 {
		return "no response bodies"
	}

	emptyBodies := 0
	decodeErrors := 0
	decodedWithoutCode := 0
	lastError := ""
	for _, attempt := range attempts {
		switch {
		case attempt.BodyLen == 0:
			emptyBodies++
		case attempt.Error != "":
			decodeErrors++
			lastError = attempt.Error
		default:
			decodedWithoutCode++
		}
	}

	if len(lastError) > 160 {
		lastError = lastError[:160] + "..."
	}
	summary := fmt.Sprintf(
		"attempts=%d empty_bodies=%d decode_errors=%d decoded_without_code=%d",
		len(attempts),
		emptyBodies,
		decodeErrors,
		decodedWithoutCode,
	)
	if lastError != "" {
		summary += fmt.Sprintf(" last_error=%q", lastError)
	}
	return summary
}

func summarizeJSLoginAttempts(attempts []JSLoginAttempt) (int, int, int, int, string) {
	emptyBodies, decodeErrors, decodedWithoutCode := 0, 0, 0
	lastError := ""
	for _, attempt := range attempts {
		switch {
		case attempt.BodyLen == 0:
			emptyBodies++
		case attempt.Error != "":
			decodeErrors++
			lastError = attempt.Error
		default:
			decodedWithoutCode++
		}
	}
	if len(lastError) > 160 {
		lastError = lastError[:160] + "..."
	}
	return len(attempts), emptyBodies, decodeErrors, decodedWithoutCode, lastError
}

func summarizeJSLoginBusinessError(attempts []JSLoginAttempt) (int64, string) {
	for _, attempt := range attempts {
		if attempt.Ret != 0 || attempt.ErrMsg != "" {
			return attempt.Ret, attempt.ErrMsg
		}
	}
	return 0, ""
}

func responseBodiesFromStage(stage StageResult) []jsLoginBodyCandidate {
	bodies := make([]jsLoginBodyCandidate, 0, len(stage.HybridBodies)+len(stage.Decoded))
	for _, body := range stage.HybridBodies {
		if len(body) == 0 {
			continue
		}
		bodies = append(bodies, jsLoginBodyCandidate{
			Source: "hybridBody",
			Body:   append([]byte{}, body...),
		})
	}

	for _, row := range stage.Decoded {
		outer := row.App.OuterFrame
		if len(outer) == 0 {
			continue
		}
		parsed, err := parseLonglinkPackHeader(outer)
		if err != nil {
			bodies = append(bodies, jsLoginBodyCandidate{
				Source: "outerFrame",
				Body:   append([]byte{}, outer...),
			})
			continue
		}

		bodies = append(bodies, jsLoginBodyCandidate{
			Source: "longlinkPack",
			Body:   append([]byte{}, parsed.Body...),
			Tag4:   parsed.IntTags[4],
			Tag23:  parsed.IntTags[23],
		})
	}
	return bodies
}

func decodeRaw89(raw89 []byte, key []byte) (JSLoginDecoded, error) {
	raw, err := unpackRaw89(raw89, key)
	if err != nil {
		return JSLoginDecoded{}, err
	}
	return decodeJsLoginResponse(raw), nil
}

func unpackRaw89(raw89 []byte, key []byte) ([]byte, error) {
	compressed, err := aesGCMPackedDecrypt(key, raw89, nil)
	if err != nil {
		return nil, err
	}
	raw, err := lz4DecompressBlock(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompress raw89: %w", err)
	}
	return raw, nil
}

func aesGCMPackedDecrypt(key []byte, blob []byte, aad []byte) ([]byte, error) {
	if len(blob) <= 28 {
		return nil, fmt.Errorf("packed aes-gcm blob too short")
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("unsupported aes-gcm key length %d", len(key))
	}

	ciphertext := blob[:len(blob)-28]
	nonce := blob[len(blob)-28 : len(blob)-16]
	tag := blob[len(blob)-16:]
	payload := append(append([]byte{}, ciphertext...), tag...)
	return aesGCMDecrypt(key, nonce, payload, aad)
}

func decodeJsLoginResponse(raw []byte) JSLoginDecoded {
	codes := map[string]struct{}{}
	walkProtoForCodes(raw, codes, 0)

	directCode := ""
	if top, err := pbDecode(raw); err == nil {
		if body := firstBytes(top, 2); len(body) > 0 {
			if bodyFields, err := pbDecode(body); err == nil {
				if maybe := firstBytes(bodyFields, 3); len(maybe) > 0 {
					text := string(maybe)
					if jsLoginCodeRE.MatchString(text) {
						directCode = text
					}
				}
			}
		}
	}

	codeCandidates := make([]string, 0, len(codes))
	for code := range codes {
		codeCandidates = append(codeCandidates, code)
	}
	sort.Strings(codeCandidates)

	code := directCode
	if code == "" && len(codeCandidates) > 0 {
		code = codeCandidates[0]
	}

	ret, errMsg := findJSLoginBusinessError(raw)
	return JSLoginDecoded{
		OK:             code != "",
		Code:           code,
		Ret:            ret,
		ErrMsg:         errMsg,
		CodeCandidates: codeCandidates,
	}
}

func findJSLoginBusinessError(raw []byte) (int64, string) {
	var walk func([]byte, int) (int64, string, bool)
	walk = func(buf []byte, depth int) (int64, string, bool) {
		if len(buf) == 0 || depth > 4 {
			return 0, "", false
		}
		fields, err := pbDecode(buf)
		if err != nil {
			return 0, "", false
		}
		if retRaw, ok := firstVarint(fields, 1); ok {
			msg := printableASCII(firstBytes(fields, 2))
			ret := signed64(retRaw)
			if ret != 0 || msg != "" {
				return ret, msg, true
			}
		}
		for _, values := range fields {
			for _, value := range values {
				if ret, msg, ok := walk(value.Bytes, depth+1); ok {
					return ret, msg, true
				}
			}
		}
		return 0, "", false
	}
	ret, msg, _ := walk(raw, 0)
	return ret, msg
}

func walkProtoForCodes(buf []byte, out map[string]struct{}, depth int) {
	if len(buf) == 0 || depth > 5 {
		return
	}

	fields, err := pbDecode(buf)
	if err != nil {
		return
	}

	for _, values := range fields {
		for _, value := range values {
			if len(value.Bytes) == 0 {
				continue
			}
			if text := printableASCII(value.Bytes); jsLoginCodeRE.MatchString(text) {
				out[text] = struct{}{}
			}
			walkProtoForCodes(value.Bytes, out, depth+1)
		}
	}
}

func printableASCII(buf []byte) string {
	if len(buf) == 0 || !utf8.Valid(buf) {
		return ""
	}

	text := string(buf)
	printable := 0
	total := 0
	for _, r := range text {
		total++
		switch {
		case r == '\t', r == '\n', r == '\r':
			printable++
		case r >= 32 && r <= 126:
			printable++
		}
	}
	if total == 0 {
		return ""
	}
	if float64(printable)/float64(total) < 0.85 {
		return ""
	}
	return text
}
