package native

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"yyb-auth-service/internal/model"
	"yyb-auth-service/internal/session"
)

const (
	oauthAuthorizeCGI       = "/ilink/ilinkapp/mm/bizoauth/oauth_authorize"
	oauthConfirmCGI         = "/ilink/ilinkapp/mm/bizoauth/oauth_authorize_confirm"
	oauthRouteCode          = 4313
	oauthTransferCmdID      = JSLoginTaskID
	oauthShortcloudPathID   = "00003c88"
	oauthAuthorizeOpt       = 1
	oauthShortcloudKeyBytes = 12
)

var ErrOAuthSessionExpired = errors.New("oauth session expired")

type OAuthAuthorizeInput struct {
	AppID            string
	AuthorizationURL string
	BizUsername      string
	Scene            int
	ReferrerURL      string
	SubScene         *int
	AutoOAuth        *bool
}

type OAuthConfirmInput struct {
	AppID            string
	AuthorizationURL string
	AvatarID         string
}

type OAuthScopeInfo struct {
	Scope       string `json:"scope"`
	Desc        string `json:"desc"`
	AuthState   int64  `json:"auth_state"`
	ExtDesc     string `json:"ext_desc"`
	AuthSubDesc string `json:"auth_sub_desc"`
}

type OAuthAvatarInfo struct {
	ID        string `json:"id"`
	Nickname  string `json:"nickname"`
	AvatarURL string `json:"avatarurl"`
}

type OAuthResult struct {
	OK                  bool                 `json:"ok"`
	Ret                 int64                `json:"ret"`
	ErrMsg              string               `json:"errmsg,omitempty"`
	RedirectURL         string               `json:"-"`
	IsRecentHasAuth     bool                 `json:"is_recent_has_auth"`
	IsSilentAuth        bool                 `json:"is_silent_auth"`
	ScopeList           []OAuthScopeInfo     `json:"scope_list"`
	AvatarList          []OAuthAvatarInfo    `json:"avatar_list"`
	UpdatedSavedSession session.SavedSession `json:"-"`
}

type oauthPackedRequest struct {
	Frame             []byte
	PackRequestAESKey []byte
	ResponseAESKey    []byte
	ResponseAESKeyAlt []byte
}

func (e *Engine) OAuthAuthorize(
	ctx context.Context,
	account model.Account,
	input OAuthAuthorizeInput,
) (OAuthResult, error) {
	return e.oauthRequest(ctx, account, input.AppID, input.AuthorizationURL, input.BizUsername,
		input.Scene, input.ReferrerURL, input.SubScene, input.AutoOAuth, "authorize")
}

func (e *Engine) OAuthConfirm(
	ctx context.Context,
	account model.Account,
	input OAuthConfirmInput,
) (OAuthResult, error) {
	return e.oauthRequest(ctx, account, input.AppID, input.AuthorizationURL, "", 0, "", nil, nil,
		"confirm", input.AvatarID)
}

func (e *Engine) oauthRequest(
	ctx context.Context,
	account model.Account,
	appID string,
	authorizationURL string,
	bizUsername string,
	scene int,
	referrerURL string,
	subScene *int,
	autoOAuth *bool,
	kind string,
	extra ...string,
) (OAuthResult, error) {
	appID = strings.TrimSpace(appID)
	authorizationURL = strings.TrimSpace(authorizationURL)
	if appID == "" {
		return OAuthResult{}, fmt.Errorf("appid required")
	}
	if authorizationURL == "" {
		return OAuthResult{}, fmt.Errorf("authorization url required")
	}

	account, fresh, err := e.freshLoginBuffer(ctx, account)
	if err != nil {
		return OAuthResult{}, err
	}
	saved, err := buildSavedSession(account)
	if err != nil {
		return OAuthResult{}, err
	}
	result := OAuthResult{ScopeList: []OAuthScopeInfo{}, AvatarList: []OAuthAvatarInfo{}}
	finish := func() OAuthResult {
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
		return finish(), fmt.Errorf("%w: manualauth baseRet=%d authSect=%t msg=%s",
			ErrOAuthSessionExpired, manualResult.BaseRet, manualResult.HasAuthSect,
			firstNonEmpty(manualResult.ErrMsg, "unknown"))
	}

	accessTicket, err := longlink.deriveShortcloudAccessTicket(shortcloudPskTypeType1)
	if err != nil {
		return finish(), err
	}
	avatarID := ""
	if kind == "confirm" {
		if len(extra) > 0 {
			avatarID = extra[0]
		}
	}
	packed, err := buildOAuthPackedRequest(
		appID, authorizationURL, bizUsername, scene, referrerURL, subScene, autoOAuth,
		kind, avatarID, manualResult.SessionBlob,
	)
	if err != nil {
		return finish(), err
	}

	shortEndpoint, err := resolveShortcloudEndpoint(ctx, saved)
	if err != nil {
		return finish(), err
	}
	requestMaterial, err := buildShortcloudRequestMaterial(
		accessTicket.AccessPSK,
		accessTicket.SelectedPSK,
		packed.Frame,
	)
	if err != nil {
		return finish(), err
	}
	requestBody := append(append(append(append([]byte{}, requestMaterial.ClientHelloRecord...),
		requestMaterial.PrefaceRecord...), requestMaterial.EnvelopeRecord...), requestMaterial.CloseRecord...)
	shortResponse, err := sendShortcloudRequest(ctx, shortEndpoint, shortEndpoint.Host, oauthShortcloudPathID,
		requestBody, e.timeout)
	if err != nil {
		return finish(), err
	}
	if len(shortResponse.Records) == 0 {
		return finish(), fmt.Errorf("oauth shortcloud response missing")
	}

	responseKeys := deriveShortcloudResponseKeys(
		accessTicket.AccessPSK,
		requestMaterial.ClientHelloRecord,
		shortResponse.Records[0].Raw,
	)
	var responseErr error
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
			responseErr = fmt.Errorf("decrypt oauth application record: %w", err)
			continue
		}
		frameBody, err := parseOAuthTransferFrameBody(plain)
		if err != nil {
			if errors.Is(err, ErrOAuthSessionExpired) {
				return finish(), err
			}
			responseErr = err
			continue
		}
		decoded, err := decodeOAuthRaw89(frameBody, packed, kind)
		if err != nil {
			responseErr = err
			continue
		}
		result = decoded
		result.UpdatedSavedSession = saved
		return result, nil
	}
	if responseErr != nil {
		return finish(), fmt.Errorf("decode oauth response: %w", responseErr)
	}
	return finish(), fmt.Errorf("oauth response body missing")
}

func buildOAuthPackedRequest(
	appID string,
	authorizationURL string,
	bizUsername string,
	scene int,
	referrerURL string,
	subScene *int,
	autoOAuth *bool,
	kind string,
	avatarID string,
	sessionBlob []byte,
) (oauthPackedRequest, error) {
	sessionState, err := parseType5SessionBlob(sessionBlob)
	if err != nil {
		return oauthPackedRequest{}, err
	}
	sessionBase := buildSessionBaseRequest(uint32(sessionState.UIN))
	reqBody, err := buildOAuthRequestBody(authorizationURL, bizUsername, scene,
		referrerURL, subScene, autoOAuth, kind, avatarID)
	if err != nil {
		return oauthPackedRequest{}, err
	}

	nested := append(append([]byte{}, pbFieldBytes(1, sessionBase)...), reqBody...)
	path := oauthAuthorizeCGI
	if kind == "confirm" {
		path = oauthConfirmCGI
	}
	wrapper := []byte{}
	wrapper = append(wrapper, pbFieldBytes(1, sessionBase)...)
	wrapper = append(wrapper, pbFieldBytes(2, []byte(path))...)
	wrapper = append(wrapper, pbFieldBytes(3, []byte(defaultHostAppID))...)
	wrapper = append(wrapper, pbFieldVarint(4, defaultOuterField4)...)
	wrapper = append(wrapper, pbFieldBytes(5, nested)...)
	wrapper = append(wrapper, pbFieldBytes(6, []byte(appID))...)
	wrapper = append(wrapper, pbFieldVarint(7, oauthRouteCode)...)
	wrapper = append(wrapper, pbFieldVarint(8, defaultOuterField8)...)
	wrapper = append(wrapper, pbFieldBytes(9, []byte(defaultPlugin))...)
	wrapper = append(wrapper, pbFieldVarint(10, defaultOuterField10)...)

	nonce := make([]byte, oauthShortcloudKeyBytes)
	if _, err := rand.Read(nonce); err != nil {
		return oauthPackedRequest{}, fmt.Errorf("generate oauth nonce: %w", err)
	}
	outBody, _, err := packOperateWXDataWrapper(wrapper, sessionState.PackRequestAESKey, nonce)
	if err != nil {
		return oauthPackedRequest{}, err
	}
	frame, err := buildTransferFrame(outBody, profileFromType5Session(sessionState), oauthTransferCmdID)
	if err != nil {
		return oauthPackedRequest{}, err
	}
	return oauthPackedRequest{
		Frame:             frame,
		PackRequestAESKey: append([]byte{}, sessionState.PackRequestAESKey...),
		ResponseAESKey:    append([]byte{}, sessionState.ResponseAESKey...),
		ResponseAESKeyAlt: append([]byte{}, sessionState.ResponseAESKeyAlt...),
	}, nil
}

func buildOAuthRequestBody(
	authorizationURL, bizUsername string, scene int, referrerURL string,
	subScene *int, autoOAuth *bool, kind, avatarID string,
) ([]byte, error) {
	reqBody := []byte{}
	if kind == "authorize" {
		reqBody = append(reqBody, pbFieldBytes(2, []byte(authorizationURL))...)
		if bizUsername != "" {
			reqBody = append(reqBody, pbFieldBytes(3, []byte(bizUsername))...)
		}
		reqBody = append(reqBody, pbFieldVarint(4, uint64(scene))...)
		if referrerURL != "" {
			reqBody = append(reqBody, pbFieldBytes(5, []byte(referrerURL))...)
		}
		if subScene != nil {
			reqBody = append(reqBody, pbFieldVarint(6, uint64(*subScene))...)
		}
		if autoOAuth != nil {
			value := uint64(0)
			if *autoOAuth {
				value = 1
			}
			reqBody = append(reqBody, pbFieldVarint(7, value)...)
		}
	} else if kind == "confirm" {
		parsed, err := url.Parse(authorizationURL)
		if err != nil {
			return nil, fmt.Errorf("parse oauth authorization url: %w", err)
		}
		scope := parsed.Query().Get("scope")
		if scope != "snsapi_base" && scope != "snsapi_userinfo" {
			return nil, fmt.Errorf("oauth confirm requires a supported scope")
		}
		avatar := uint64(0)
		if avatarID = strings.TrimSpace(avatarID); avatarID != "" {
			avatar, err = strconv.ParseUint(avatarID, 10, 31)
			if err != nil {
				return nil, fmt.Errorf("avatar_id must be a nonnegative int32: %w", err)
			}
		}
		reqBody = append(reqBody, pbFieldBytes(2, []byte(authorizationURL))...)
		reqBody = append(reqBody, pbFieldVarint(3, oauthAuthorizeOpt)...)
		reqBody = append(reqBody, pbFieldBytes(4, []byte(scope))...)
		reqBody = append(reqBody, pbFieldVarint(5, avatar)...)
		reqBody = append(reqBody, pbFieldBytes(6, []byte(authorizationURL))...)
	} else {
		return nil, fmt.Errorf("unsupported oauth request kind %q", kind)
	}
	return reqBody, nil
}

func parseOAuthTransferFrameBody(frame []byte) ([]byte, error) {
	if len(frame) < 16 {
		return nil, fmt.Errorf("oauth transfer frame too short")
	}
	totalLen := uint32(frame[0])<<24 | uint32(frame[1])<<16 | uint32(frame[2])<<8 | uint32(frame[3])
	if int(totalLen) != len(frame) {
		return nil, fmt.Errorf("oauth transfer frame total length mismatch")
	}
	pack, err := parseLonglinkPackHeader(frame[16:])
	if err != nil {
		return nil, err
	}
	if linkErr, ok := pack.IntTags[4]; ok && linkErr != 0 {
		return nil, fmt.Errorf("%w: link_err=%d", ErrOAuthSessionExpired, linkErr)
	}
	return pack.Body, nil
}

func decodeOAuthRaw89(raw89 []byte, request oauthPackedRequest, kind string) (OAuthResult, error) {
	keys := [][]byte{request.ResponseAESKey, request.ResponseAESKeyAlt, request.PackRequestAESKey}
	var decodeErr error
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		plain, err := unpackRaw89(raw89, key)
		if err != nil {
			if decodeErr == nil {
				decodeErr = fmt.Errorf("decrypt oauth raw89 (%d bytes): %w", len(raw89), err)
			}
			continue
		}
		result, err := parseOAuthResponse(plain, kind)
		if err == nil {
			return result, nil
		}
		decodeErr = fmt.Errorf("parse oauth %s payload (%d bytes): %w", kind, len(plain), err)
	}
	if decodeErr == nil {
		decodeErr = fmt.Errorf("oauth response has no decryption keys")
	}
	return OAuthResult{}, decodeErr
}

func parseOAuthResponse(payload []byte, kind string) (OAuthResult, error) {
	if kind != "authorize" && kind != "confirm" {
		return OAuthResult{}, fmt.Errorf("unsupported oauth response kind %q", kind)
	}
	fields, err := pbDecode(payload)
	if err != nil {
		return OAuthResult{}, err
	}
	result, err := parseOAuthBaseResponse(fields)
	if err != nil || !result.OK {
		return result, err
	}
	responseFields := fields
	if nestedRaw := firstBytes(fields, 2); len(nestedRaw) > 0 {
		nestedFields, nestedErr := pbDecode(nestedRaw)
		if nestedErr != nil {
			return OAuthResult{}, fmt.Errorf("decode oauth transfer payload: %w", nestedErr)
		}
		result, err = parseOAuthBaseResponse(nestedFields)
		if err != nil || !result.OK {
			return result, err
		}
		responseFields = nestedFields
	}
	if kind == "confirm" {
		result.RedirectURL = strings.TrimSpace(string(firstBytes(responseFields, 3)))
		return result, nil
	}

	result.RedirectURL = strings.TrimSpace(string(firstBytes(responseFields, 6)))
	if value, ok := firstVarint(responseFields, 8); ok {
		result.IsRecentHasAuth = value != 0
	}
	if value, ok := firstVarint(responseFields, 9); ok {
		result.IsSilentAuth = value != 0
	}
	for _, value := range responseFields[3] {
		if value.WireType != 2 {
			return OAuthResult{}, fmt.Errorf("oauth scope has invalid wire type %d", value.WireType)
		}
		nested, err := pbDecode(value.Bytes)
		if err != nil {
			return OAuthResult{}, fmt.Errorf("decode oauth scope: %w", err)
		}
		state, _ := firstVarint(nested, 3)
		result.ScopeList = append(result.ScopeList, OAuthScopeInfo{
			Scope: string(firstBytes(nested, 1)), Desc: string(firstBytes(nested, 2)),
			AuthState: signed64(state), ExtDesc: string(firstBytes(nested, 4)),
			AuthSubDesc: string(firstBytes(nested, 5)),
		})
	}
	for _, value := range responseFields[11] {
		if value.WireType != 2 {
			return OAuthResult{}, fmt.Errorf("oauth avatar has invalid wire type %d", value.WireType)
		}
		nested, err := pbDecode(value.Bytes)
		if err != nil {
			return OAuthResult{}, fmt.Errorf("decode oauth avatar: %w", err)
		}
		id := ""
		if values := nested[1]; len(values) > 0 && values[0].WireType == 0 {
			id = fmt.Sprintf("%d", values[0].Varint)
		}
		result.AvatarList = append(result.AvatarList, OAuthAvatarInfo{
			ID: id, Nickname: string(firstBytes(nested, 2)),
			AvatarURL: string(firstBytes(nested, 3)),
		})
	}
	return result, nil
}

func parseOAuthBaseResponse(fields map[int][]PBValue) (OAuthResult, error) {
	base := firstBytes(fields, 1)
	if len(base) == 0 {
		return OAuthResult{}, fmt.Errorf("oauth response missing baseresponse")
	}
	baseFields, err := pbDecode(base)
	if err != nil {
		return OAuthResult{}, fmt.Errorf("decode oauth baseresponse: %w", err)
	}
	retRaw, ok := firstVarint(baseFields, 1)
	if !ok {
		return OAuthResult{}, fmt.Errorf("oauth response missing ret")
	}
	result := OAuthResult{
		OK:         signed64(retRaw) == 0,
		Ret:        signed64(retRaw),
		ErrMsg:     decodeOAuthMessage(firstBytes(baseFields, 2)),
		ScopeList:  []OAuthScopeInfo{},
		AvatarList: []OAuthAvatarInfo{},
	}
	return result, nil
}

func decodeOAuthMessage(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if nested, err := pbDecode(raw); err == nil {
		if text := firstBytes(nested, 1); len(text) > 0 {
			return string(text)
		}
	}
	return string(raw)
}
