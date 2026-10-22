package native

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	shortcloudPathID          = "000041d2"
	shortcloudTransferPath    = "/ilink/ilinkapp/mp/wxaruntime_transfer"
	shortcloudEnvelopeHost    = "shortcloud.weixin.com"
	shortcloudPskTypeType1    = 1
	shortcloudClientHelloType = 0x19
	shortcloudPrefaceType     = 0x19
	shortcloudApplicationType = 0x17
	shortcloudCloseType       = 0x15
)

var (
	shortcloudPrefacePlain = []byte{
		0x00, 0x00, 0x00, 0x10,
		0x08, 0x00, 0x00, 0x00,
		0x0b, 0x01, 0x00, 0x00,
		0x00, 0x06, 0x00, 0x12,
		0x6a, 0x26, 0x95, 0x79,
	}
	shortcloudClosePlain = []byte{0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01}
)

type serializedPSK struct {
	Type int
	Raw  []byte
}

type shortcloudAccessTicket struct {
	AccessPSK   []byte
	SelectedPSK serializedPSK
}

type shortcloudRequestMaterial struct {
	ClientHelloRecord []byte
	PrefaceRecord     []byte
	EnvelopeRecord    []byte
	CloseRecord       []byte
}

type shortcloudResponse struct {
	StatusLine string
	Headers    map[string]string
	Records    []mmtlsRecord
}

func (s *LonglinkSession) deriveShortcloudAccessTicket(
	pskType int,
) (shortcloudAccessTicket, error) {
	if s == nil {
		return shortcloudAccessTicket{}, fmt.Errorf("longlink session is nil")
	}
	if len(s.handshake.Stage2Secret) == 0 {
		return shortcloudAccessTicket{}, fmt.Errorf("longlink handshake stage2 secret missing")
	}
	if len(s.handshake.ClientHelloRecord) == 0 || len(s.handshake.ServerHelloRecord) == 0 {
		return shortcloudAccessTicket{}, fmt.Errorf("longlink handshake hello record missing")
	}
	if len(s.handshake.ServerHandshakePlain) < 2 {
		return shortcloudAccessTicket{}, fmt.Errorf("longlink handshake new-session payload missing")
	}

	psks, err := parseNewSessionPSKs(s.handshake.ServerHandshakePlain[1])
	if err != nil {
		return shortcloudAccessTicket{}, err
	}
	selected, err := selectPSKByType(psks, pskType)
	if err != nil {
		return shortcloudAccessTicket{}, err
	}
	accessPSK := deriveAccessPSK(
		s.handshake.Stage2Secret,
		s.handshake.ClientHelloRecord,
		s.handshake.ServerHelloRecord,
		s.handshake.ServerHandshakePlain[0],
	)
	return shortcloudAccessTicket{
		AccessPSK:   accessPSK,
		SelectedPSK: selected,
	}, nil
}

func parseNewSessionPSKs(plain []byte) ([]serializedPSK, error) {
	if len(plain) < 10 {
		return nil, fmt.Errorf("new-session handshake plain too short")
	}
	msgLen := binary.BigEndian.Uint32(plain[:4])
	if int(msgLen)+4 != len(plain) || plain[4] != 0x04 {
		return nil, fmt.Errorf("not a valid new-session handshake message")
	}

	count := int(plain[5])
	offset := 6
	rows := make([]serializedPSK, 0, count)
	for range count {
		if offset+4 > len(plain) {
			return nil, fmt.Errorf("truncated psk length")
		}
		size := int(binary.BigEndian.Uint32(plain[offset : offset+4]))
		offset += 4
		end := offset + size
		if end > len(plain) {
			return nil, fmt.Errorf("truncated psk body")
		}
		raw := append([]byte{}, plain[offset:end]...)
		rows = append(rows, serializedPSK{
			Type: int(raw[0]),
			Raw:  raw,
		})
		offset = end
	}
	if offset != len(plain) {
		return nil, fmt.Errorf("new-session trailing bytes")
	}
	return rows, nil
}

func selectPSKByType(psks []serializedPSK, pskType int) (serializedPSK, error) {
	for _, row := range psks {
		if row.Type == pskType {
			return row, nil
		}
	}
	return serializedPSK{}, fmt.Errorf("server new-session response has no type%d access PSK", pskType)
}

func deriveAccessPSK(
	stage2Secret []byte,
	clientHelloRecord []byte,
	serverHelloRecord []byte,
	serverPlain1 []byte,
) []byte {
	context := transcriptHash(
		recordPayload(clientHelloRecord),
		recordPayload(serverHelloRecord),
		serverPlain1,
	)
	return mmtlsExpand(stage2Secret, "PSK_ACCESS", context, 32)
}

func buildShortcloudRequestMaterial(
	accessPSK []byte,
	selectedPSK serializedPSK,
	frame []byte,
) (shortcloudRequestMaterial, error) {
	clientNonce36 := make([]byte, 36)
	if _, err := rand.Read(clientNonce36); err != nil {
		return shortcloudRequestMaterial{}, fmt.Errorf("generate shortcloud nonce: %w", err)
	}

	clientHelloRecord, err := buildShortcloudClientHelloRecord(clientNonce36, selectedPSK.Raw)
	if err != nil {
		return shortcloudRequestMaterial{}, err
	}
	earlyKeys := deriveShortcloudEarlyKeys(accessPSK, clientHelloRecord)
	envelope := buildShortcloudEnvelope(frame)

	prefaceRecord, err := encryptRawMMTLSRecord(
		shortcloudPrefacePlain,
		earlyKeys,
		1,
		shortcloudPrefaceType,
	)
	if err != nil {
		return shortcloudRequestMaterial{}, err
	}
	envelopeRecord, err := encryptRawMMTLSRecord(
		envelope,
		earlyKeys,
		2,
		shortcloudApplicationType,
	)
	if err != nil {
		return shortcloudRequestMaterial{}, err
	}
	closeRecord, err := encryptRawMMTLSRecord(
		shortcloudClosePlain,
		earlyKeys,
		3,
		shortcloudCloseType,
	)
	if err != nil {
		return shortcloudRequestMaterial{}, err
	}

	return shortcloudRequestMaterial{
		ClientHelloRecord: clientHelloRecord,
		PrefaceRecord:     prefaceRecord,
		EnvelopeRecord:    envelopeRecord,
		CloseRecord:       closeRecord,
	}, nil
}

func buildShortcloudClientHelloRecord(
	clientNonce36 []byte,
	pskSerialized []byte,
) ([]byte, error) {
	if len(clientNonce36) != 36 {
		return nil, fmt.Errorf("client_nonce36 must be 36 bytes, got %d", len(clientNonce36))
	}

	suite := []byte{0x01, 0x00, 0xa8}
	pskBody := append([]byte{0x01}, make([]byte, 4)...)
	binary.BigEndian.PutUint32(pskBody[1:5], uint32(len(pskSerialized)))
	pskBody = append(pskBody, pskSerialized...)

	pskExt := make([]byte, 0, len(pskBody)+6)
	pskExt = append(pskExt, 0, 0, 0, 0, 0x00, 0x0f)
	binary.BigEndian.PutUint32(pskExt[0:4], uint32(len(pskBody)+2))
	pskExt = append(pskExt, pskBody...)

	extensions := append([]byte{0x01}, pskExt...)
	body := make([]byte, 0, len(pskSerialized)+64)
	body = append(body, 0x01, 0x03, 0xf1)
	body = append(body, suite...)
	body = append(body, clientNonce36...)

	extensionsLen := make([]byte, 4)
	binary.BigEndian.PutUint32(extensionsLen, uint32(len(extensions)))
	body = append(body, extensionsLen...)
	body = append(body, extensions...)

	payloadLen := make([]byte, 4)
	binary.BigEndian.PutUint32(payloadLen, uint32(len(body)))
	payload := append(payloadLen, body...)
	record := append(
		recordHeader(shortcloudClientHelloType, uint16(len(payload))),
		payload...,
	)
	return record, nil
}

func deriveShortcloudEarlyKeys(
	accessPSK []byte,
	clientHelloRecord []byte,
) connKeys {
	context := sha256Sum(recordPayload(clientHelloRecord))
	block := mmtlsExpand(accessPSK, "early data key expansion", context, 28)
	return connKeys{
		Key: append([]byte{}, block[:16]...),
		IV:  append([]byte{}, block[16:28]...),
	}
}

func deriveShortcloudResponseKeys(
	accessPSK []byte,
	clientHelloRecord []byte,
	serverHelloRecord []byte,
) connKeys {
	context := transcriptHash(
		recordPayload(clientHelloRecord),
		shortcloudPrefacePlain,
		recordPayload(serverHelloRecord),
	)
	block := mmtlsExpand(accessPSK, "handshake key expansion", context, 28)
	return connKeys{
		Key: append([]byte{}, block[:16]...),
		IV:  append([]byte{}, block[16:28]...),
	}
}

func buildShortcloudEnvelope(frame []byte) []byte {
	path := []byte(shortcloudTransferPath)
	host := []byte(shortcloudEnvelopeHost)
	rest := make([]byte, 0, len(frame)+len(path)+len(host)+8)

	pathLen := make([]byte, 2)
	binary.BigEndian.PutUint16(pathLen, uint16(len(path)))
	hostLen := make([]byte, 2)
	binary.BigEndian.PutUint16(hostLen, uint16(len(host)))
	frameLen := make([]byte, 4)
	binary.BigEndian.PutUint32(frameLen, uint32(len(frame)))

	rest = append(rest, pathLen...)
	rest = append(rest, path...)
	rest = append(rest, hostLen...)
	rest = append(rest, host...)
	rest = append(rest, frameLen...)
	rest = append(rest, frame...)

	total := make([]byte, 4)
	binary.BigEndian.PutUint32(total, uint32(len(rest)))
	return append(total, rest...)
}

func encryptRawMMTLSRecord(
	plain []byte,
	keys connKeys,
	seq uint64,
	recordType byte,
) ([]byte, error) {
	payloadLen := len(plain) + 16
	if payloadLen > 65535 {
		return nil, fmt.Errorf("shortcloud record payload exceeds 65535 bytes")
	}
	aad := buildAAD(recordType, uint16(payloadLen), seq)
	nonce, err := gcmNonce(keys.IV, seq)
	if err != nil {
		return nil, err
	}
	payload, err := aesGCMEncrypt(keys.Key, nonce, plain, aad)
	if err != nil {
		return nil, err
	}
	return append(recordHeader(recordType, uint16(len(payload))), payload...), nil
}

func sendShortcloudRequest(
	ctx context.Context,
	endpoint LonglinkEndpoint,
	hostHeader string,
	pathID string,
	body []byte,
	timeout time.Duration,
) (shortcloudResponse, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(
		ctx,
		"tcp",
		net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)),
	)
	if err != nil {
		return shortcloudResponse{}, fmt.Errorf("dial shortcloud: %w", err)
	}
	defer conn.Close()
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()

	request := buildShortcloudHTTPRequest(hostHeader, pathID, body)
	if err := writeRecordWithContext(ctx, conn, request, timeout); err != nil {
		return shortcloudResponse{}, fmt.Errorf("write shortcloud request: %w", err)
	}

	rawResponse, err := readShortcloudHTTPResponseWithContext(ctx, conn, timeout)
	if err != nil {
		return shortcloudResponse{}, err
	}
	statusLine, headers, responseBody, err := parseShortcloudHTTPResponse(rawResponse)
	if err != nil {
		return shortcloudResponse{}, err
	}
	records, err := splitMMTLSRecords(responseBody)
	if err != nil {
		return shortcloudResponse{}, err
	}
	return shortcloudResponse{
		StatusLine: statusLine,
		Headers:    headers,
		Records:    records,
	}, nil
}

func buildShortcloudHTTPRequest(hostHeader string, pathID string, body []byte) []byte {
	headers := []string{
		"POST /mmtls/" + pathID + " HTTP/1.0",
		"Accept: */*",
		"Cache-Control: no-cache",
		"Connection: close",
		"Content-Length: " + strconv.Itoa(len(body)),
		"Content-Type: application/octet-stream",
		"Host: " + hostHeader,
		"Upgrade: mmtls",
		"User-Agent: MicroMessenger Client",
		"X-Online-Host: " + hostHeader,
		"",
		"",
	}
	return append([]byte(strings.Join(headers, "\r\n")), body...)
}

func readShortcloudHTTPResponse(conn net.Conn, timeout time.Duration) ([]byte, error) {
	return readShortcloudHTTPResponseWithContext(context.Background(), conn, timeout)
}

func readShortcloudHTTPResponseWithContext(ctx context.Context, conn net.Conn, timeout time.Duration) ([]byte, error) {
	const maxHeaderBytes = 64 << 10
	const maxResponseBytes = 16 << 20
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	chunks := make([]byte, 0, 8192)
	buf := make([]byte, 8192)
	headerEnd := -1
	contentLength := -1

	for {
		if err := conn.SetReadDeadline(connectionDeadline(ctx, timeout)); err != nil {
			return nil, fmt.Errorf("set shortcloud read deadline: %w", connectionError(ctx, err))
		}

		n, err := conn.Read(buf)
		if n > 0 {
			chunks = append(chunks, buf[:n]...)
			if len(chunks) > maxResponseBytes {
				return nil, fmt.Errorf("shortcloud response exceeds 16 MiB")
			}
			if headerEnd < 0 {
				headerEnd = strings.Index(string(chunks), "\r\n\r\n")
				if headerEnd > maxHeaderBytes || (headerEnd < 0 && len(chunks) > maxHeaderBytes) {
					return nil, fmt.Errorf("shortcloud HTTP header exceeds 64 KiB")
				}
				if headerEnd >= 0 {
					var headerErr error
					contentLength, headerErr = validatedHTTPContentLength(chunks[:headerEnd])
					if headerErr != nil {
						return nil, headerErr
					}
					if contentLength > maxResponseBytes-headerEnd-4 {
						return nil, fmt.Errorf("shortcloud response content length exceeds 16 MiB")
					}
				}
			}
			if headerEnd >= 0 && contentLength >= 0 {
				bodyLen := len(chunks) - headerEnd - 4
				if bodyLen >= contentLength {
					return chunks[:headerEnd+4+contentLength], nil
				}
			}
		}
		if err != nil {
			err = connectionError(ctx, err)
			if err == io.EOF {
				if headerEnd >= 0 && contentLength >= 0 && len(chunks)-headerEnd-4 < contentLength {
					return nil, fmt.Errorf("shortcloud response body truncated: %w", io.ErrUnexpectedEOF)
				}
				return chunks, nil
			}
			return nil, fmt.Errorf("read shortcloud response: %w", err)
		}
	}
}

func parseShortcloudHTTPResponse(
	raw []byte,
) (string, map[string]string, []byte, error) {
	sep := strings.Index(string(raw), "\r\n\r\n")
	if sep < 0 {
		return "", nil, nil, fmt.Errorf("HTTP response header terminator not found")
	}
	head := string(raw[:sep])
	body := append([]byte{}, raw[sep+4:]...)
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 {
		return "", nil, nil, fmt.Errorf("HTTP response head empty")
	}
	status := strings.Fields(lines[0])
	if len(status) < 2 || (status[0] != "HTTP/1.0" && status[0] != "HTTP/1.1") {
		return "", nil, nil, fmt.Errorf("invalid shortcloud HTTP status line %q", lines[0])
	}
	statusCode, err := strconv.Atoi(status[1])
	if err != nil || len(status[1]) != 3 || statusCode < 100 || statusCode > 599 {
		return "", nil, nil, fmt.Errorf("invalid shortcloud HTTP status line %q", lines[0])
	}
	if statusCode < 200 || statusCode >= 300 {
		return "", nil, nil, fmt.Errorf("shortcloud HTTP rejected: %s", lines[0])
	}
	length, err := validatedHTTPContentLength(raw[:sep])
	if err != nil {
		return "", nil, nil, err
	}
	if length >= 0 && length != len(body) {
		return "", nil, nil, fmt.Errorf("shortcloud HTTP content length mismatch: %w", io.ErrUnexpectedEOF)
	}

	headers := make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
	}
	return lines[0], headers, body, nil
}

func parseHTTPContentLength(head []byte) int {
	length, err := validatedHTTPContentLength(head)
	if err != nil {
		return -1
	}
	return length
}

func validatedHTTPContentLength(head []byte) (int, error) {
	length := -1
	lines := strings.Split(string(head), "\r\n")
	for _, line := range lines[1:] {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		if name == "transfer-encoding" && strings.TrimSpace(parts[1]) != "" {
			return -1, fmt.Errorf("unsupported shortcloud HTTP transfer encoding %q", strings.TrimSpace(parts[1]))
		}
		if name != "content-length" {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || value < 0 {
			return -1, fmt.Errorf("invalid shortcloud HTTP content length %q", strings.TrimSpace(parts[1]))
		}
		if length >= 0 && length != value {
			return -1, fmt.Errorf("conflicting shortcloud HTTP content lengths")
		}
		length = value
	}
	return length, nil
}

func splitMMTLSRecords(raw []byte) ([]mmtlsRecord, error) {
	records := make([]mmtlsRecord, 0, 4)
	offset := 0
	for offset < len(raw) {
		if offset+5 > len(raw) {
			return nil, fmt.Errorf("truncated MMTLS record header")
		}
		payloadLen := int(binary.BigEndian.Uint16(raw[offset+3 : offset+5]))
		end := offset + 5 + payloadLen
		if end > len(raw) {
			return nil, fmt.Errorf("truncated MMTLS record payload")
		}
		recordRaw := append([]byte{}, raw[offset:end]...)
		records = append(records, mmtlsRecord{
			RecordType: raw[offset],
			PayloadLen: uint16(payloadLen),
			Raw:        recordRaw,
		})
		offset = end
	}
	return records, nil
}

func recordPayload(record []byte) []byte {
	if len(record) <= 5 {
		return []byte{}
	}
	return append([]byte{}, record[5:]...)
}

func transcriptHash(parts ...[]byte) []byte {
	merged := []byte{}
	for _, part := range parts {
		merged = append(merged, part...)
	}
	return sha256Sum(merged)
}

func mmtlsExpand(secret []byte, label string, context []byte, outLen int) []byte {
	info := append([]byte(label), context...)
	return hkdfExpand(secret, info, outLen)
}
