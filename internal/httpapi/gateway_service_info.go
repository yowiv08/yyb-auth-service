package httpapi

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	gatewayServiceInfoAPIName  = "tcbapi_get_service_info"
	gatewayDefaultSystem       = "Android 12"
	gatewayDefaultWXAppVersion = "8.0.74"
	gatewayDefaultSDKVersion   = "wx-miniprogram-sdk/3.16.2 (1783510673000 platform/android})"
	gatewayDefaultScene        = 3
	gatewayDefaultEnv          = 1
	gatewayDefaultRV           = "2"
)

type gatewayServiceInfoInput struct {
	System           string `json:"system"`
	WXAppVersion     string `json:"wx_app_version"`
	Scene            int    `json:"scene"`
	KX               string `json:"kx"`
	ClientPrivateKey string `json:"client_private_key"`
	SDKVersion       string `json:"sdk_version"`
	SessionID        string `json:"session_id"`
	CLIReqID         string `json:"cli_req_id"`
	RID              string `json:"rid"`
	RV               string `json:"rv"`
	Env              int    `json:"env"`
}

type gatewayServiceInfoQBaseReq struct {
	System       string `json:"system"`
	WXAppVersion string `json:"wx_app_version"`
	Scene        int    `json:"scene"`
	KX           string `json:"kx"`
}

type gatewayServiceInfoQBaseOptions struct {
	RID string `json:"rid"`
	RV  string `json:"rv"`
}

type gatewayServiceInfoQBaseMeta struct {
	SessionID  string `json:"session_id"`
	SDKVersion string `json:"sdk_version"`
}

type gatewayServiceInfoQBaseData struct {
	QBaseAPIName string                         `json:"qbase_api_name"`
	QBaseReq     string                         `json:"qbase_req"`
	QBaseOptions gatewayServiceInfoQBaseOptions `json:"qbase_options"`
	QBaseMeta    gatewayServiceInfoQBaseMeta    `json:"qbase_meta"`
	CLIReqID     string                         `json:"cli_req_id"`
}

type gatewayServiceInfoOperateData struct {
	APIName         string                      `json:"api_name"`
	Data            gatewayServiceInfoQBaseData `json:"data"`
	OperateDirectly bool                        `json:"operate_directly"`
	Env             int                         `json:"env"`
}

func buildQBaseGatewayServiceInfoData(
	rawData json.RawMessage,
	now time.Time,
) (operateWXDataPreparedData, error) {
	var input gatewayServiceInfoInput
	decoder := json.NewDecoder(bytes.NewReader(rawData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return operateWXDataPreparedData{}, fmt.Errorf("decode gateway service info data: %w", err)
	}

	system := strings.TrimSpace(input.System)
	if system == "" {
		system = gatewayDefaultSystem
	}
	wxAppVersion := strings.TrimSpace(input.WXAppVersion)
	if wxAppVersion == "" {
		wxAppVersion = gatewayDefaultWXAppVersion
	}
	scene := input.Scene
	if scene == 0 {
		scene = gatewayDefaultScene
	}
	if scene < 0 {
		return operateWXDataPreparedData{}, fmt.Errorf("data.scene must be greater than 0")
	}
	sdkVersion := strings.TrimSpace(input.SDKVersion)
	if sdkVersion == "" {
		sdkVersion = gatewayDefaultSDKVersion
	}
	env := input.Env
	if env == 0 {
		env = gatewayDefaultEnv
	}
	if env < 0 || env > 255 {
		return operateWXDataPreparedData{}, fmt.Errorf("data.env must be between 1 and 255")
	}

	clientPrivateKey, clientKX, err := gatewayClientKeyPair(input)
	if err != nil {
		return operateWXDataPreparedData{}, err
	}

	currentTime := now.UnixMilli()
	sessionID := strings.TrimSpace(input.SessionID)
	if sessionID == "" {
		sessionID = strconv.FormatInt(currentTime, 10)
	}
	cliReqID := strings.TrimSpace(input.CLIReqID)
	if cliReqID == "" {
		cliRandomValue, err := randomDecimalString()
		if err != nil {
			return operateWXDataPreparedData{}, err
		}
		cliReqID = fmt.Sprintf("%d_%s", currentTime, cliRandomValue)
	}

	qbaseReqPayload, err := json.Marshal(gatewayServiceInfoQBaseReq{
		System:       system,
		WXAppVersion: wxAppVersion,
		Scene:        scene,
		KX:           clientKX,
	})
	if err != nil {
		return operateWXDataPreparedData{}, fmt.Errorf("encode gateway qbase_req: %w", err)
	}

	rv := strings.TrimSpace(input.RV)
	if rv == "" {
		rv = gatewayDefaultRV
	}
	rid := strings.TrimSpace(input.RID)
	if rid == "" {
		rid = generateGatewayRIDAt(
			cliReqID,
			sdkVersion,
			string(qbaseReqPayload),
			byte(env),
			strconv.FormatInt(currentTime, 10),
		)
	}

	payload := gatewayServiceInfoOperateData{
		APIName: "qbase_commapi",
		Data: gatewayServiceInfoQBaseData{
			QBaseAPIName: gatewayServiceInfoAPIName,
			QBaseReq:     string(qbaseReqPayload),
			QBaseOptions: gatewayServiceInfoQBaseOptions{
				RID: rid,
				RV:  rv,
			},
			QBaseMeta: gatewayServiceInfoQBaseMeta{
				SessionID:  sessionID,
				SDKVersion: sdkVersion,
			},
			CLIReqID: cliReqID,
		},
		OperateDirectly: false,
		Env:             env,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return operateWXDataPreparedData{}, fmt.Errorf("encode gateway qbase_commapi data: %w", err)
	}

	return operateWXDataPreparedData{
		DataString: string(payloadJSON),
		GatewayServiceInfoRequest: &gatewayServiceInfoRequest{
			RID:              rid,
			Source:           gatewayServiceInfoAPIName,
			ClientKX:         clientKX,
			ClientPrivateKey: clientPrivateKey,
		},
	}, nil
}

func gatewayClientKeyPair(input gatewayServiceInfoInput) (privateHex, publicHex string, err error) {
	privateHex = strings.TrimSpace(input.ClientPrivateKey)
	publicHex = strings.TrimSpace(input.KX)

	if privateHex == "" {
		if publicHex != "" {
			if err := validateX25519PublicKey(publicHex); err != nil {
				return "", "", fmt.Errorf("invalid data.kx: %w", err)
			}
			return "", strings.ToLower(publicHex), nil
		}
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return "", "", fmt.Errorf("generate gateway X25519 key: %w", err)
		}
		return hex.EncodeToString(privateKey.Bytes()),
			hex.EncodeToString(privateKey.PublicKey().Bytes()), nil
	}

	privateBytes, err := hex.DecodeString(privateHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid data.client_private_key: %w", err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return "", "", fmt.Errorf("invalid data.client_private_key: %w", err)
	}
	derivedPublicHex := hex.EncodeToString(privateKey.PublicKey().Bytes())
	if publicHex == "" {
		return strings.ToLower(privateHex), derivedPublicHex, nil
	}
	if err := validateX25519PublicKey(publicHex); err != nil {
		return "", "", fmt.Errorf("invalid data.kx: %w", err)
	}
	if !strings.EqualFold(publicHex, derivedPublicHex) {
		return "", "", fmt.Errorf("data.kx does not match data.client_private_key")
	}
	return strings.ToLower(privateHex), strings.ToLower(publicHex), nil
}

func validateX25519PublicKey(value string) error {
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	_, err = ecdh.X25519().NewPublicKey(raw)
	return err
}

func generateGatewayRIDAt(
	cliReqID string,
	sdkVersion string,
	qbaseReq string,
	envByte byte,
	timestamp string,
) string {
	input := []byte(timestamp + cliReqID + sdkVersion + qbaseReq)
	input = append(input, envByte)
	firstLo, firstHi, secondLo, secondHi := gatewayRIDHashWords(input, envByte)
	return fmt.Sprintf(
		"%08x%08x-%s-%08x%08x",
		firstHi,
		firstLo,
		timestamp,
		secondHi,
		secondLo,
	)
}

func gatewayRIDHashWords(data []byte, envByte byte) (uint32, uint32, uint32, uint32) {
	q := uint32(2216829733)
	g := uint32(3421674724)
	const x = uint32(435)
	u := uint32(256)
	o := uint32(1650920142)
	rHi := uint32(5)

	for _, by := range data {
		q0 := o
		p := rHi
		var de uint32
		o, de = gatewayRIDRotl64(o, rHi, 17)
		d, fe := gatewayRIDRotl64(q0, rHi, 9)
		rSum := fe + de
		m := d + o
		b := rSum
		if m < d {
			b++
		}
		oAnd := o & d
		rMix := uint32(((uint64(de&fe) << 1) | uint64(oAnd>>31)) & 0xffffffff)
		d2 := oAnd << 1
		o = q0 ^ (m - d2)
		prodLo, prodHi := gatewayRIDMul64(uint32(by)^q, g, x, u)
		q = prodLo ^ o
		borrow := uint32(0)
		if m < d2 {
			borrow = 1
		}
		rHi = (b - (borrow + rMix)) ^ p
		g = rHi ^ prodHi
	}

	firstLo, firstHi := q, g
	q ^= uint32(2800111026)
	g ^= uint32(1861519497)
	addLo := uint32(envByte) + q
	addHi := g
	if addLo < uint32(envByte) {
		addHi++
	}
	x2, rotHi := gatewayRIDRotl64(addLo, addHi, 5)
	oHi := g + rotHi
	rLo := x2 + q
	if rLo < q {
		oHi++
	}
	x2 &= q
	carry := uint32(((uint64(rotHi&g) << 1) | uint64(x2>>31)) & 0xffffffff)
	q2 := x2 << 1
	secondLo := rLo - q2
	borrow := uint32(0)
	if rLo < q2 {
		borrow = 1
	}
	secondHi := oHi - (borrow + carry)
	return firstLo, firstHi, secondLo, secondHi
}

func gatewayRIDRotl64(lo, hi uint32, bits uint) (uint32, uint32) {
	value := (uint64(hi) << 32) | uint64(lo)
	bits &= 63
	rotated := (value << bits) | (value >> (64 - bits))
	return uint32(rotated), uint32(rotated >> 32)
}

func gatewayRIDMul64(lo1, hi1, lo2, hi2 uint32) (uint32, uint32) {
	left := (uint64(hi1) << 32) | uint64(lo1)
	right := (uint64(hi2) << 32) | uint64(lo2)
	product := left * right
	return uint32(product), uint32(product >> 32)
}
