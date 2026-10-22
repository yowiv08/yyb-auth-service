package native

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"yyb-auth-service/internal/session"
)

const (
	clientNID              = 415
	hybridType             = 1
	defaultServerField2    = 1901
	defaultServerPubKeyB64 = "BO+Hh21keLFfF5bqsSBoYQVBFztxdrZ/HcyGaD6QGs1E0YtKw2k4JR0IEt0M+EKqLWy7gRVxLRwAh9zvwUpEzVg="
)

var precryptoPrefix = []byte{0xf0, 0xd4}

type TDIContext struct {
	DeviceIDB64   string
	IlinkAppID    string
	LoginType     int
	ProductID     int
	WorkDirectory string
}

type ManualAuthRequest struct {
	PlainInfo     ManualAuthPlainInfo
	HybridRequest []byte
	RequestState  hybridRequestState
}

type ManualAuthPlainInfo struct {
	DeviceIDB64 string
	DeviceIDHex string
	ServerField int
	LoginType   int
	ProductID   int
	SlotID      int
	Route       string
	Body        []byte
}

type Type5Session struct {
	PackRequestAESKey []byte
	ResponseAESKey    []byte
	ResponseAESKeyAlt []byte
	UIN               uint64
	Field27           []byte
	SessionBlob       []byte
}

type ManualAuthResult struct {
	OK             bool
	BaseRet        int
	ErrMsg         string
	HasAuthSect    bool
	HasNetworkSect bool
	UIN            string
	LZ4Block       []byte
	Plain          []byte
	SessionBlob    []byte
	ProtocolTDI    map[string]any
}

type hybridRequestState struct {
	ClientNID uint64
	Private   *ecdh.PrivateKey
	ClientPub []byte
	HKDF56    []byte
	Precrypto []byte
}

type hybridBuildOptions struct {
	PrivateKeyBytes []byte
	Random32        []byte
	Field3Nonce     []byte
	Field5Nonce     []byte
}

func buildTDIContext(
	deviceIDB64 string,
) TDIContext {
	return TDIContext{
		DeviceIDB64:   deviceIDB64,
		IlinkAppID:    IlinkAppID,
		LoginType:     4,
		ProductID:     0,
		WorkDirectory: filepath.ToSlash("virtual/tdi/" + IlinkAppID + "/0/6"),
	}
}

func buildManualAuthRequest(
	tdiCtx TDIContext,
	loginBufferB64 string,
) (ManualAuthRequest, error) {
	plainInfo, err := buildPlainBody(tdiCtx, loginBufferB64)
	if err != nil {
		return ManualAuthRequest{}, err
	}

	request, requestState, err := buildHybridRequest(plainInfo.Body)
	if err != nil {
		return ManualAuthRequest{}, err
	}

	return ManualAuthRequest{
		PlainInfo:     plainInfo,
		HybridRequest: request,
		RequestState:  requestState,
	}, nil
}

func buildPlainBody(
	tdiCtx TDIContext,
	loginBufferB64 string,
) (ManualAuthPlainInfo, error) {
	deviceIDRaw, err := decodeBase64(tdiCtx.DeviceIDB64)
	if err != nil {
		return ManualAuthPlainInfo{}, fmt.Errorf("decode device id: %w", err)
	}
	if len(deviceIDRaw) != 16 && len(deviceIDRaw) != 32 {
		return ManualAuthPlainInfo{}, fmt.Errorf("unexpected device id length %d", len(deviceIDRaw))
	}

	loginTokenField, err := parseLoginBufferFirstField(loginBufferB64)
	if err != nil {
		return ManualAuthPlainInfo{}, err
	}

	slotID := slotIDFromWorkDir(tdiCtx.WorkDirectory)
	parts := [][]byte{
		pbFieldBytes(1, pbFieldBytes(1, deviceIDRaw)),
		pbFieldVarint(2, defaultServerField2),
		pbFieldBytes(3, loginTokenField),
		pbFieldVarint(4, uint64(tdiCtx.LoginType)),
		pbFieldBytes(6, []byte{}),
		pbFieldVarint(7, uint64(tdiCtx.ProductID)),
		pbFieldVarint(8, uint64(slotID)),
	}

	body := []byte{}
	for _, part := range parts {
		body = append(body, part...)
	}

	return ManualAuthPlainInfo{
		DeviceIDB64: tdiCtx.DeviceIDB64,
		DeviceIDHex: hex.EncodeToString(deviceIDRaw),
		ServerField: defaultServerField2,
		LoginType:   tdiCtx.LoginType,
		ProductID:   tdiCtx.ProductID,
		SlotID:      slotID,
		Route:       firstNonEmpty(tdiCtx.IlinkAppID, IlinkAppID),
		Body:        body,
	}, nil
}

func buildHybridRequest(plainBody []byte) ([]byte, hybridRequestState, error) {
	return buildHybridRequestWithOptions(plainBody, hybridBuildOptions{})
}

func buildHybridRequestWithOptions(
	plainBody []byte,
	opts hybridBuildOptions,
) ([]byte, hybridRequestState, error) {
	serverPubKeyRaw, err := base64.StdEncoding.DecodeString(defaultServerPubKeyB64)
	if err != nil {
		return nil, hybridRequestState{}, fmt.Errorf("decode server pubkey: %w", err)
	}

	var privateKey *ecdh.PrivateKey
	if len(opts.PrivateKeyBytes) > 0 {
		privateKey, err = ecdh.P256().NewPrivateKey(opts.PrivateKeyBytes)
		if err != nil {
			return nil, hybridRequestState{}, fmt.Errorf("parse hybrid private key: %w", err)
		}
	} else {
		privateKey, err = ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, hybridRequestState{}, fmt.Errorf("generate hybrid key: %w", err)
		}
	}
	clientPub := privateKey.PublicKey().Bytes()
	serverPub, err := ecdh.P256().NewPublicKey(serverPubKeyRaw)
	if err != nil {
		return nil, hybridRequestState{}, fmt.Errorf("parse server pubkey: %w", err)
	}
	sharedReq, err := privateKey.ECDH(serverPub)
	if err != nil {
		return nil, hybridRequestState{}, fmt.Errorf("compute request secret: %w", err)
	}

	random32 := append([]byte{}, opts.Random32...)
	if len(random32) == 0 {
		random32 = make([]byte, 32)
		if _, err := rand.Read(random32); err != nil {
			return nil, hybridRequestState{}, fmt.Errorf("generate random32: %w", err)
		}
	}
	if len(random32) != 32 {
		return nil, hybridRequestState{}, fmt.Errorf("random32 must be 32B")
	}
	field3Nonce := append([]byte{}, opts.Field3Nonce...)
	if len(field3Nonce) == 0 {
		field3Nonce = make([]byte, 12)
		if _, err := rand.Read(field3Nonce); err != nil {
			return nil, hybridRequestState{}, fmt.Errorf("generate field3 nonce: %w", err)
		}
	}
	if len(field3Nonce) != 12 {
		return nil, hybridRequestState{}, fmt.Errorf("field3 nonce must be 12B")
	}
	field5Nonce := append([]byte{}, opts.Field5Nonce...)
	if len(field5Nonce) == 0 {
		field5Nonce = make([]byte, 12)
		if _, err := rand.Read(field5Nonce); err != nil {
			return nil, hybridRequestState{}, fmt.Errorf("generate field5 nonce: %w", err)
		}
	}
	if len(field5Nonce) != 12 {
		return nil, hybridRequestState{}, fmt.Errorf("field5 nonce must be 12B")
	}

	sharedReqHash := sha256Sum(sharedReq)
	aad1Base := []byte{}
	aad1Base = append(aad1Base, []byte(strconv.Itoa(hybridType))...)
	aad1Base = append(aad1Base, []byte(strconv.Itoa(clientNID))...)
	aad1Base = append(aad1Base, clientPub...)
	aad1 := sha256Sum(aad1Base)
	field3, err := aesGCMEncrypt192Packed(sharedReqHash[:24], random32, field3Nonce, aad1)
	if err != nil {
		return nil, hybridRequestState{}, err
	}

	prk := hmacSha256([]byte("security hdkf expand"), random32)
	hkdf56 := hkdfExpand(prk, aad1, 56)
	precrypto := append(append([]byte{}, precryptoPrefix...), plainBody...)
	aad2Base := []byte{}
	aad2Base = append(aad2Base, []byte(strconv.Itoa(hybridType))...)
	aad2Base = append(aad2Base, []byte(strconv.Itoa(clientNID))...)
	aad2Base = append(aad2Base, clientPub...)
	aad2Base = append(aad2Base, field3...)
	aad2 := sha256Sum(aad2Base)
	field5, err := aesGCMEncrypt192Packed(hkdf56[:24], precrypto, field5Nonce, aad2)
	if err != nil {
		return nil, hybridRequestState{}, err
	}

	secKey := []byte{}
	secKey = append(secKey, pbFieldVarint(1, uint64(clientNID))...)
	secKey = append(secKey, pbFieldBytes(2, clientPub)...)

	request := []byte{}
	request = append(request, pbFieldVarint(1, uint64(hybridType))...)
	request = append(request, pbFieldBytes(2, secKey)...)
	request = append(request, pbFieldBytes(3, field3)...)
	request = append(request, pbFieldBytes(4, []byte{})...)
	request = append(request, pbFieldBytes(5, field5)...)

	return request, hybridRequestState{
		ClientNID: uint64(clientNID),
		Private:   privateKey,
		ClientPub: clientPub,
		HKDF56:    hkdf56,
		Precrypto: precrypto,
	}, nil
}

func decodeManualAuthStage(
	stage StageResult,
	requestState hybridRequestState,
	saved *session.SavedSession,
) (ManualAuthResult, error) {
	var body []byte
	for _, candidate := range stage.HybridBodies {
		if len(candidate) > 0 {
			body = candidate
			break
		}
	}
	if len(body) == 0 {
		return ManualAuthResult{
			OK:             false,
			HasAuthSect:    false,
			HasNetworkSect: false,
		}, nil
	}

	block, err := decryptHybridLZ4Block(body, requestState)
	if err != nil {
		return ManualAuthResult{}, err
	}

	plain, err := lz4DecompressBlock(block)
	if err != nil {
		return ManualAuthResult{}, fmt.Errorf("decompress manualauth lz4 block: %w", err)
	}

	parsed, err := applyManualAuthPlaintext(plain, saved)
	if err != nil {
		return ManualAuthResult{}, err
	}

	var sessionBlob []byte
	if parsed.HasAuthSect || parsed.BaseRet == 0 {
		sessionBlob, err = extractSessionBlobFromResponse(plain)
		if err != nil {
			return ManualAuthResult{}, err
		}
		saved.ProtocolTDI["sessionBlobB64"] = base64.StdEncoding.EncodeToString(sessionBlob)
	}

	parsed.LZ4Block = block
	parsed.Plain = plain
	parsed.SessionBlob = sessionBlob
	return parsed, nil
}

func decryptHybridLZ4Block(
	responseBody []byte,
	requestState hybridRequestState,
) ([]byte, error) {
	fields, err := pbDecode(responseBody)
	if err != nil {
		return nil, fmt.Errorf("decode hybrid response: %w", err)
	}

	secRaw := firstBytes(fields, 1)
	if len(secRaw) == 0 {
		return nil, fmt.Errorf("hybrid response field1 missing")
	}
	sec, err := pbDecode(secRaw)
	if err != nil {
		return nil, fmt.Errorf("decode hybrid response field1: %w", err)
	}
	responsePubRaw := firstBytes(sec, 2)
	if len(responsePubRaw) == 0 {
		return nil, fmt.Errorf("hybrid response pubkey missing")
	}
	responsePub, err := ecdh.P256().NewPublicKey(responsePubRaw)
	if err != nil {
		return nil, fmt.Errorf("parse hybrid response pubkey: %w", err)
	}
	credentialType, _ := firstVarint(fields, 2)
	encrypted := firstBytes(fields, 3)
	if len(encrypted) == 0 {
		return nil, fmt.Errorf("hybrid response field3 missing")
	}

	sharedResp, err := requestState.Private.ECDH(responsePub)
	if err != nil {
		return nil, fmt.Errorf("compute response secret: %w", err)
	}
	sharedRespHash := sha256Sum(sharedResp)

	aad3 := []byte{}
	aad3 = append(aad3, requestState.HKDF56[24:]...)
	aad3 = append(aad3, requestState.Precrypto...)
	aad3 = append(aad3, []byte(strconv.FormatUint(requestState.ClientNID, 10))...)
	aad3 = append(aad3, responsePubRaw...)
	aad3 = append(aad3, []byte(strconv.FormatUint(credentialType, 10))...)
	aad3 = sha256Sum(aad3)

	return aesGCMDecrypt192Packed(sharedRespHash[:24], encrypted, aad3)
}

func extractSessionBlobFromResponse(payload []byte) ([]byte, error) {
	top, err := pbDecode(payload)
	if err != nil {
		return nil, fmt.Errorf("decode manualauth payload: %w", err)
	}
	authBody := firstBytes(top, 3)
	if len(authBody) == 0 {
		return nil, fmt.Errorf("manualauth auth body missing")
	}
	auth, err := pbDecode(authBody)
	if err != nil {
		return nil, fmt.Errorf("decode auth body: %w", err)
	}
	appSessionStateRaw := firstBytes(auth, 2)
	accountStateRaw := firstBytes(auth, 3)
	if len(appSessionStateRaw) == 0 || len(accountStateRaw) == 0 {
		return nil, fmt.Errorf("manualauth session state missing")
	}
	appSessionState, err := pbDecode(appSessionStateRaw)
	if err != nil {
		return nil, fmt.Errorf("decode app session state: %w", err)
	}
	accountState, err := pbDecode(accountStateRaw)
	if err != nil {
		return nil, fmt.Errorf("decode account state: %w", err)
	}

	field1 := firstBytes(appSessionState, 1)
	field2 := firstBytes(appSessionState, 2)
	field3 := firstBytes(appSessionState, 4)
	field5 := firstBytes(appSessionState, 9)
	field4, ok := firstVarint(accountState, 1)
	if len(field1) == 0 || len(field2) == 0 || len(field3) == 0 || len(field5) == 0 || !ok {
		return nil, fmt.Errorf("manualauth session blob fields missing")
	}

	blob := []byte{}
	blob = append(blob, pbFieldBytes(1, field1)...)
	blob = append(blob, pbFieldBytes(2, field2)...)
	blob = append(blob, pbFieldBytes(3, field3)...)
	blob = append(blob, pbFieldVarint(4, field4)...)
	blob = append(blob, pbFieldBytes(5, field5)...)
	return blob, nil
}

func parseType5SessionBlob(blob []byte) (Type5Session, error) {
	fields, err := pbDecode(blob)
	if err != nil {
		return Type5Session{}, fmt.Errorf("decode session blob: %w", err)
	}

	uin, ok := firstVarint(fields, 4)
	if !ok {
		return Type5Session{}, fmt.Errorf("session blob uin missing")
	}

	session := Type5Session{
		PackRequestAESKey: append([]byte{}, firstBytes(fields, 1)...),
		ResponseAESKey:    append([]byte{}, firstBytes(fields, 2)...),
		ResponseAESKeyAlt: append([]byte{}, firstBytes(fields, 3)...),
		UIN:               uin,
		Field27:           append([]byte{}, firstBytes(fields, 5)...),
		SessionBlob:       append([]byte{}, blob...),
	}
	if len(session.PackRequestAESKey) == 0 || len(session.Field27) == 0 {
		return Type5Session{}, fmt.Errorf("session blob fields missing")
	}
	return session, nil
}

func applyManualAuthPlaintext(
	plain []byte,
	saved *session.SavedSession,
) (ManualAuthResult, error) {
	top, err := pbDecode(plain)
	if err != nil {
		return ManualAuthResult{}, fmt.Errorf("decode manualauth plaintext: %w", err)
	}

	baseRet := 0
	errMsg := ""
	if baseRaw := firstBytes(top, 1); len(baseRaw) > 0 {
		baseFields, decodeErr := pbDecode(baseRaw)
		if decodeErr != nil {
			return ManualAuthResult{}, fmt.Errorf("decode manualauth base: %w", decodeErr)
		}
		if value, ok := firstVarint(baseFields, 1); ok {
			baseRet = int(value)
		}
		if text := firstBytes(baseFields, 2); len(text) > 0 {
			errMsg = string(text)
		}
	}

	unifyFields := map[int][]PBValue{}
	if unifyRaw := firstBytes(top, 3); len(unifyRaw) > 0 {
		unifyFields, err = pbDecode(unifyRaw)
		if err != nil {
			return ManualAuthResult{}, fmt.Errorf("decode manualauth unify: %w", err)
		}
	}

	hasAuthSect := len(firstBytes(unifyFields, 2)) > 0
	hasNetworkSect := len(firstBytes(unifyFields, 5)) > 0
	uin := ""

	if acctRaw := firstBytes(unifyFields, 3); len(acctRaw) > 0 {
		acctFields, decodeErr := pbDecode(acctRaw)
		if decodeErr != nil {
			return ManualAuthResult{}, fmt.Errorf("decode account state: %w", decodeErr)
		}
		if value, ok := firstVarint(acctFields, 1); ok {
			uin = strconv.FormatUint(value, 10)
		}
	}

	if saved.ProtocolTDI == nil {
		saved.ProtocolTDI = map[string]any{}
	}
	protocolTDI := saved.ProtocolTDI

	if netRaw := firstBytes(unifyFields, 5); len(netRaw) > 0 {
		networkSect, parseErr := parseNetworkSect(netRaw)
		if parseErr != nil {
			return ManualAuthResult{}, parseErr
		}
		protocolTDI["networkSectB64"] = base64.StdEncoding.EncodeToString(netRaw)
		protocolTDI["networkSectFields"] = networkSect["fields"]

		hostTables, err := parseNetworkSectHosts(netRaw)
		if err == nil {
			protocolTDI["networkSectHosts"] = map[string]any{
				"strategy":   hostTables.Strategy,
				"longcloud":  hostTables.Longcloud,
				"shortcloud": hostTables.Shortcloud,
			}
			if ipv4 := pickIPv4(flattenIPs(hostTables.Longcloud)); ipv4 != "" {
				protocolTDI["longcloudHost"] = ipv4
			}
		}

	}

	protocolTDI["updatedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
	protocolTDI["lastBaseRet"] = baseRet
	if uin != "" {
		protocolTDI["uin"] = uin
	}

	if hasAuthSect {
		authRaw := firstBytes(unifyFields, 2)
		authSect, parseErr := parseAuthSect(authRaw)
		if parseErr != nil {
			return ManualAuthResult{}, parseErr
		}
		for key, value := range authSect {
			protocolTDI[key] = value
		}
		protocolTDI["hasAuthSect"] = true
	}
	if hasNetworkSect {
		protocolTDI["hasNetworkSect"] = true
	}
	if saved.TokenInfo.OpenID != "" {
		protocolTDI["username"] = saved.TokenInfo.OpenID + "@im." + IlinkAppID
	}
	saved.ProtocolTDI = protocolTDI

	return ManualAuthResult{
		OK:             baseRet == 0 && hasAuthSect,
		BaseRet:        baseRet,
		ErrMsg:         errMsg,
		HasAuthSect:    hasAuthSect,
		HasNetworkSect: hasNetworkSect,
		UIN:            uin,
		ProtocolTDI:    protocolTDI,
	}, nil
}

func parseNetworkSect(netRaw []byte) (map[string]any, error) {
	fields, err := pbDecode(netRaw)
	if err != nil {
		return nil, fmt.Errorf("decode network sect payload: %w", err)
	}

	result := map[string]any{
		"fields": map[string]any{},
	}
	fieldMap := result["fields"].(map[string]any)
	for field, values := range fields {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		if len(value.Bytes) > 0 {
			b64 := base64.StdEncoding.EncodeToString(value.Bytes)
			fieldMap[strconv.Itoa(field)] = map[string]any{
				"type":    "bytes",
				"len":     len(value.Bytes),
				"b64Head": b64[:min(len(b64), 24)],
			}
			continue
		}

		fieldMap[strconv.Itoa(field)] = map[string]any{
			"type":  "varint",
			"value": strconv.FormatUint(value.Varint, 10),
		}
	}
	return result, nil
}

func parseAuthSect(authRaw []byte) (map[string]any, error) {
	fields, err := pbDecode(authRaw)
	if err != nil {
		return nil, fmt.Errorf("decode auth sect: %w", err)
	}

	result := map[string]any{
		"authSectB64": base64.StdEncoding.EncodeToString(authRaw),
	}
	summary := map[string]any{
		"rawLen":       len(authRaw),
		"fieldLengths": map[string]any{},
		"fieldVarints": map[string]any{},
	}
	fieldLengths := summary["fieldLengths"].(map[string]any)
	fieldVarints := summary["fieldVarints"].(map[string]any)
	for field, values := range fields {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		if len(value.Bytes) > 0 {
			fieldLengths[strconv.Itoa(field)] = len(value.Bytes)
		} else {
			fieldVarints[strconv.Itoa(field)] = strconv.FormatUint(value.Varint, 10)
		}
	}

	field1 := firstBytes(fields, 1)
	field2 := firstBytes(fields, 2)
	autoauthKey := firstBytes(fields, 3)
	field4 := firstBytes(fields, 4)
	field8 := firstBytes(fields, 8)
	field9 := firstBytes(fields, 9)
	field12 := firstBytes(fields, 12)

	result["authSect"] = summary
	result["authSectField1B64"] = base64.StdEncoding.EncodeToString(field1)
	result["authSectField2B64"] = base64.StdEncoding.EncodeToString(field2)
	result["authSectField4B64"] = base64.StdEncoding.EncodeToString(field4)
	result["authSectField8B64"] = base64.StdEncoding.EncodeToString(field8)
	result["authSectField9B64"] = base64.StdEncoding.EncodeToString(field9)
	result["authSectField12B64"] = base64.StdEncoding.EncodeToString(field12)

	if len(autoauthKey) > 0 {
		result["autoauthKeyB64"] = base64.StdEncoding.EncodeToString(autoauthKey)
		result["autoauthKeyLen"] = len(autoauthKey)
	}
	if value, ok := firstVarint(fields, 5); ok {
		result["authSectField5"] = strconv.FormatUint(value, 10)
	}
	if value, ok := firstVarint(fields, 7); ok {
		result["authSectField7"] = strconv.FormatUint(value, 10)
	}

	if len(field1) > 0 && len(field2) > 0 {
		first := hkdfSHA256(field1, field2, []byte("cloudsessionkey"), 48)
		alt := hkdfSHA256(field2, field1, []byte("cloudsessionkey"), 48)
		result["cloudSessionKeyFirstB64"] = base64.StdEncoding.EncodeToString(first[:24])
		result["autoauthEncKeyB64"] = base64.StdEncoding.EncodeToString(first[24:48])
		result["sessionKeyB64"] = base64.StdEncoding.EncodeToString(first[24:48])
		result["autoauthEncKeyAltB64"] = base64.StdEncoding.EncodeToString(alt[24:48])
		summary["hkdf"] = map[string]any{
			"saltField":        1,
			"ikmField":         2,
			"info":             "cloudsessionkey",
			"outLen":           48,
			"firstKeyB64":      base64.StdEncoding.EncodeToString(first[:24]),
			"sessionKeyB64":    base64.StdEncoding.EncodeToString(first[24:48]),
			"altSessionKeyB64": base64.StdEncoding.EncodeToString(alt[24:48]),
		}
	}

	return result, nil
}

func resolveSessionKey(protocolTDI map[string]any) ([]byte, string, error) {
	source := "hkdf12-second"
	value, _ := protocolTDI["sessionKeyB64"].(string)
	if strings.TrimSpace(value) == "" {
		return nil, "", fmt.Errorf("sessionKeyB64 missing in protocol tdi")
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, "", fmt.Errorf("decode session key: %w", err)
	}
	return key, source, nil
}

func parseLoginBufferFirstField(loginBufferB64 string) ([]byte, error) {
	raw, err := decodeBase64(strings.ReplaceAll(loginBufferB64, " ", ""))
	if err != nil {
		return nil, fmt.Errorf("decode login buffer: %w", err)
	}
	fields, err := pbDecode(raw)
	if err != nil {
		return nil, fmt.Errorf("decode login buffer fields: %w", err)
	}
	token := firstBytes(fields, 1)
	if len(token) == 0 {
		return nil, fmt.Errorf("login_buffer field1 not found")
	}
	return pbFieldBytes(1, token), nil
}

func slotIDFromWorkDir(workDir string) int {
	name := filepath.Base(strings.ReplaceAll(workDir, "\\", "/"))
	slot, err := strconv.Atoi(name)
	if err != nil {
		return 6
	}
	return slot
}

func hkdfSHA256(salt []byte, ikm []byte, info []byte, outLen int) []byte {
	prk := hmacSha256(salt, ikm)
	return hkdfExpand(prk, info, outLen)
}

func protocolTDIString(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func min(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func marshalProtocolTDI(values map[string]any) string {
	payload, err := json.Marshal(values)
	if err != nil {
		return "{}"
	}
	return string(payload)
}
