package native

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	mmtlsVersion             = 0xf103
	mmtlsAppRecordType       = 0x17
	mmtlsHandshakeRecordType = 0x16
	mmtlsFinishedHandshake   = 0x14
	transferWord1            = 0x1110076d
)

var cipherSuites = []uint16{0xc02b, 0x00a8}

var errIncompleteMMTLSRecord = errors.New("incomplete MMTLS record")

type connKeys struct {
	Key []byte
	IV  []byte
}

type appPlain struct {
	TotalLen   uint32
	Word1      uint32
	TaskID     uint32
	TaskType   int32
	OuterFrame []byte
}

type mmtlsRecord struct {
	RecordType byte
	PayloadLen uint16
	Raw        []byte
}

type decodedAppRecord struct {
	Seq uint64
	App appPlain
}

type PackedStage struct {
	Profile      LonglinkProfile
	IdentityMode string
	Body         []byte
	Seq          uint64
	TaskID       uint32
	TaskType     int32
	Timeout      time.Duration
}

type StageResult struct {
	Seq          uint64
	TaskID       uint32
	TaskType     int32
	OuterFrame   []byte
	Decoded      []decodedAppRecord
	HybridBodies [][]byte
}

type LonglinkSession struct {
	conn        net.Conn
	sendAppKeys connKeys
	recvAppKeys connKeys
	timeout     time.Duration
	handshake   longlinkHandshake
}

type share struct {
	Version uint32
	Private *ecdh.PrivateKey
	Public  []byte
}

type longlinkHandshake struct {
	ClientFinishedRecord []byte
	SendAppKeys          connKeys
	RecvAppKeys          connKeys
	ClientHelloRecord    []byte
	ServerHelloRecord    []byte
	ServerHandshakePlain [][]byte
	Stage2Secret         []byte
}

func openLonglinkSession(
	ctx context.Context,
	host string,
	port int,
	timeout time.Duration,
	sendAck bool,
) (*LonglinkSession, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(
		ctx,
		"tcp",
		fmt.Sprintf("%s:%d", host, port),
	)
	if err != nil {
		return nil, fmt.Errorf("dial longlink: %w", err)
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()

	clientShares, helloRecord, err := buildClientHelloRecord()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err := writeRecordWithContext(ctx, conn, helloRecord, timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}

	serverRecords := make([]mmtlsRecord, 0, 4)
	for range 4 {
		record, recvErr := recvOneRecordWithContext(ctx, conn, timeout)
		if recvErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("receive server flight: %w", recvErr)
		}
		serverRecords = append(serverRecords, record)
	}

	handshake, err := deriveFreshHandshake(helloRecord, serverRecords, clientShares)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err := writeRecordWithContext(ctx, conn, handshake.ClientFinishedRecord, timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}

	session := &LonglinkSession{
		conn:        conn,
		sendAppKeys: handshake.SendAppKeys,
		recvAppKeys: handshake.RecvAppKeys,
		timeout:     timeout,
		handshake:   handshake,
	}

	if sendAck {
		ackRecord, err := encryptAppRecord(
			[]byte{},
			session.sendAppKeys,
			2,
			6,
			-1,
		)
		if err != nil {
			session.Close()
			return nil, err
		}
		if err := writeRecordWithContext(ctx, conn, ackRecord, timeout); err != nil {
			session.Close()
			return nil, err
		}
	}

	return session, nil
}

func (s *LonglinkSession) Close() {
	if s == nil || s.conn == nil {
		return
	}
	_ = s.conn.Close()
}

func (s *LonglinkSession) SendPackedBody(
	ctx context.Context,
	stage PackedStage,
) (StageResult, error) {
	timeout := stage.Timeout
	if timeout <= 0 {
		timeout = s.timeout
	}

	header, err := buildLonglinkPackHeader(stage.Profile, stage.IdentityMode)
	if err != nil {
		return StageResult{}, err
	}
	outerFrame := make([]byte, 0, len(header)+len(stage.Body))
	outerFrame = append(outerFrame, header...)
	outerFrame = append(outerFrame, stage.Body...)

	record, err := encryptAppRecord(
		outerFrame,
		s.sendAppKeys,
		stage.Seq,
		stage.TaskID,
		stage.TaskType,
	)
	if err != nil {
		return StageResult{}, err
	}

	if err := writeRecordWithContext(ctx, s.conn, record, timeout); err != nil {
		return StageResult{}, err
	}

	responseRecords, err := recvAllRecordsWithContext(ctx, s.conn, timeout)
	if err != nil {
		return StageResult{}, err
	}

	decoded := tryDecodeAppRecords(responseRecords, s.recvAppKeys)
	hybridBodies := make([][]byte, 0, len(decoded))
	for _, row := range decoded {
		body, extractErr := extractHybridBodyFromOuter(row.App.OuterFrame)
		if extractErr == nil && len(body) > 0 {
			hybridBodies = append(hybridBodies, body)
		}
	}

	return StageResult{
		Seq:          stage.Seq,
		TaskID:       stage.TaskID,
		TaskType:     stage.TaskType,
		OuterFrame:   outerFrame,
		Decoded:      decoded,
		HybridBodies: hybridBodies,
	}, nil
}

func buildClientHelloRecord() ([]share, []byte, error) {
	clientShares := make([]share, 0, 2)
	for _, version := range []uint32{1, 2} {
		privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate p256 key: %w", err)
		}
		clientShares = append(clientShares, share{
			Version: version,
			Private: privateKey,
			Public:  privateKey.PublicKey().Bytes(),
		})
	}

	clientNonce := make([]byte, 36)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, nil, fmt.Errorf("generate client nonce: %w", err)
	}

	exts := make([]byte, 0, 128)
	keyshareExt, err := buildKeyshareExt(clientShares)
	if err != nil {
		return nil, nil, err
	}
	exts = append(exts, keyshareExt...)

	suitePart := []byte{byte(len(cipherSuites))}
	for _, suite := range cipherSuites {
		entry := make([]byte, 2)
		binary.BigEndian.PutUint16(entry, suite)
		suitePart = append(suitePart, entry...)
	}

	inner := make([]byte, 0, 256)
	inner = append(inner, 0x01)
	inner = append(inner, 0x03, 0xf1)
	inner = append(inner, suitePart...)
	inner = append(inner, clientNonce...)

	extTotal := len(exts) + 1
	extLen := make([]byte, 4)
	binary.BigEndian.PutUint32(extLen, uint32(extTotal))
	inner = append(inner, extLen...)
	inner = append(inner, byte(1))
	inner = append(inner, exts...)

	payloadLen := make([]byte, 4)
	binary.BigEndian.PutUint32(payloadLen, uint32(len(inner)))
	payload := append(payloadLen, inner...)
	record := append(recordHeader(
		mmtlsHandshakeRecordType,
		uint16(len(payload)),
	), payload...)

	return clientShares, record, nil
}

func buildKeyshareExt(clientShares []share) ([]byte, error) {
	body := []byte{byte(len(clientShares))}
	for _, row := range clientShares {
		entryBody := make([]byte, 0, 4+2+len(row.Public))
		version := make([]byte, 4)
		binary.BigEndian.PutUint32(version, row.Version)
		entryBody = append(entryBody, version...)
		pubLen := make([]byte, 2)
		binary.BigEndian.PutUint16(pubLen, uint16(len(row.Public)))
		entryBody = append(entryBody, pubLen...)
		entryBody = append(entryBody, row.Public...)

		entryLen := make([]byte, 4)
		binary.BigEndian.PutUint32(entryLen, uint32(len(entryBody)))
		body = append(body, entryLen...)
		body = append(body, entryBody...)
	}

	body = append(body, 0, 0, 0, 1)
	extLen := make([]byte, 4)
	binary.BigEndian.PutUint32(extLen, uint32(len(body)+2))
	out := append(extLen, 0x00, 0x10)
	out = append(out, body...)
	return out, nil
}

func deriveFreshHandshake(
	clientHelloRecord []byte,
	serverRecords []mmtlsRecord,
	clientShares []share,
) (longlinkHandshake, error) {
	if len(serverRecords) < 4 {
		return longlinkHandshake{}, fmt.Errorf("server flight needs 4 records")
	}

	serverHello := serverRecords[0].Raw
	serverShare, err := parseServerHello(serverHello)
	if err != nil {
		return longlinkHandshake{}, err
	}

	selected, err := selectShare(clientShares, serverShare.Version)
	if err != nil {
		return longlinkHandshake{}, err
	}

	serverPub, err := ecdh.P256().NewPublicKey(serverShare.Public)
	if err != nil {
		return longlinkHandshake{}, fmt.Errorf("parse server public key: %w", err)
	}
	secret, err := selected.Private.ECDH(serverPub)
	if err != nil {
		return longlinkHandshake{}, fmt.Errorf("compute ecdh secret: %w", err)
	}
	stage2Secret := sha256Sum(secret)

	stage2Hash := transcriptPayloadHash(
		clientHelloRecord[5:],
		serverHello[5:],
	)
	handshakeBlock := splitConnKeyBlock(
		hkdfExpand(
			stage2Secret,
			append([]byte("handshake key expansion"), stage2Hash...),
			56,
		),
	)

	serverPlains := make([][]byte, 0, 3)
	for seq := uint64(1); seq <= 3; seq++ {
		plain, decryptErr := decryptHandshakeRecord(
			serverRecords[seq].Raw,
			connKeys{
				Key: handshakeBlock.ServerWriteKey,
				IV:  handshakeBlock.ServerWriteIV,
			},
			seq,
		)
		if decryptErr != nil {
			return longlinkHandshake{}, decryptErr
		}
		serverPlains = append(serverPlains, plain)
	}

	preFinishedHash := transcriptPayloadHash(
		clientHelloRecord[5:],
		serverHello[5:],
		serverPlains[0],
		serverPlains[1],
	)
	serverVerify, err := parseFinishedPlain(serverPlains[2])
	if err != nil {
		return longlinkHandshake{}, err
	}
	expectedServerVerify := finishedVerifyData(
		stage2Secret,
		preFinishedHash,
		"server",
	)
	if string(serverVerify) != string(expectedServerVerify) {
		return longlinkHandshake{}, fmt.Errorf("server finished verify mismatch")
	}

	clientVerify := finishedVerifyData(
		stage2Secret,
		preFinishedHash,
		"client",
	)
	clientFinishedRecord, err := encryptHandshakeRecord(
		buildFinishedPlain(clientVerify),
		connKeys{
			Key: handshakeBlock.ClientWriteKey,
			IV:  handshakeBlock.ClientWriteIV,
		},
		1,
	)
	if err != nil {
		return longlinkHandshake{}, err
	}

	expandedSecret := hkdfExpand(
		stage2Secret,
		append([]byte("expanded secret"), preFinishedHash...),
		32,
	)
	appBlock := splitConnKeyBlock(
		hkdfExpand(
			expandedSecret,
			append([]byte("application data key expansion"), preFinishedHash...),
			56,
		),
	)

	return longlinkHandshake{
		ClientFinishedRecord: clientFinishedRecord,
		SendAppKeys: connKeys{
			Key: appBlock.ClientWriteKey,
			IV:  appBlock.ClientWriteIV,
		},
		RecvAppKeys: connKeys{
			Key: appBlock.ServerWriteKey,
			IV:  appBlock.ServerWriteIV,
		},
		ClientHelloRecord: append([]byte{}, clientHelloRecord...),
		ServerHelloRecord: append([]byte{}, serverHello...),
		ServerHandshakePlain: [][]byte{
			append([]byte{}, serverPlains[0]...),
			append([]byte{}, serverPlains[1]...),
			append([]byte{}, serverPlains[2]...),
		},
		Stage2Secret: append([]byte{}, stage2Secret...),
	}, nil
}

type keyBlock struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
}

func splitConnKeyBlock(block []byte) keyBlock {
	return keyBlock{
		ClientWriteKey: append([]byte{}, block[0:16]...),
		ServerWriteKey: append([]byte{}, block[16:32]...),
		ClientWriteIV:  append([]byte{}, block[32:44]...),
		ServerWriteIV:  append([]byte{}, block[44:56]...),
	}
}

func parseServerHello(record []byte) (share, error) {
	payload := record[5:]
	if len(payload) < 48 {
		return share{}, fmt.Errorf("server hello too short")
	}

	offset := 4 + 1 + 2 + 2 + 32 + 4
	if offset >= len(payload) {
		return share{}, fmt.Errorf("server hello extension count missing")
	}
	extCount := int(payload[offset])
	offset++

	for index := 0; index < extCount; index++ {
		if offset+6 > len(payload) {
			return share{}, fmt.Errorf("server hello extension truncated")
		}
		extLen := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
		offset += 4
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		offset += 2
		bodyLen := extLen - 2
		if bodyLen < 0 || offset+bodyLen > len(payload) {
			return share{}, fmt.Errorf("server hello extension body truncated")
		}
		body := payload[offset : offset+bodyLen]
		offset += bodyLen

		if extType != 0x0011 {
			continue
		}
		if len(body) < 6 {
			return share{}, fmt.Errorf("server keyshare body too short")
		}
		version := binary.BigEndian.Uint32(body[0:4])
		pubLen := int(binary.BigEndian.Uint16(body[4:6]))
		if 6+pubLen > len(body) {
			return share{}, fmt.Errorf("server keyshare public key truncated")
		}
		return share{
			Version: version,
			Public:  append([]byte{}, body[6:6+pubLen]...),
		}, nil
	}

	return share{}, fmt.Errorf("server hello key share missing")
}

func selectShare(clientShares []share, version uint32) (share, error) {
	for _, row := range clientShares {
		if row.Version == version {
			return row, nil
		}
	}
	return share{}, fmt.Errorf("no matching client share for server version %d", version)
}

func transcriptPayloadHash(payloads ...[]byte) []byte {
	hash := sha256.New()
	for _, payload := range payloads {
		_, _ = hash.Write(payload)
	}
	return hash.Sum(nil)
}

func finishedVerifyData(
	stage2Secret []byte,
	transcriptHash []byte,
	role string,
) []byte {
	label := "client finished"
	if role == "server" {
		label = "server finished"
	}
	return hmacSha256(
		hkdfExpand(stage2Secret, []byte(label), 32),
		transcriptHash,
	)
}

func buildFinishedPlain(verifyData []byte) []byte {
	body := make([]byte, 0, 1+2+len(verifyData))
	body = append(body, mmtlsFinishedHandshake)
	body = append(body, 0, 32)
	body = append(body, verifyData...)

	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)))
	return append(length, body...)
}

func parseFinishedPlain(plain []byte) ([]byte, error) {
	if len(plain) < 39 {
		return nil, fmt.Errorf("finished plain too short")
	}
	length := int(binary.BigEndian.Uint16(plain[5:7]))
	if 7+length > len(plain) {
		return nil, fmt.Errorf("finished verify data truncated")
	}
	return append([]byte{}, plain[7:7+length]...), nil
}

func encryptHandshakeRecord(
	plain []byte,
	keys connKeys,
	seq uint64,
) ([]byte, error) {
	payloadLen := len(plain) + 16
	aad := buildAAD(mmtlsHandshakeRecordType, uint16(payloadLen), seq)
	nonce, err := gcmNonce(keys.IV, seq)
	if err != nil {
		return nil, err
	}
	payload, err := aesGCMEncrypt(keys.Key, nonce, plain, aad)
	if err != nil {
		return nil, err
	}
	record := append(recordHeader(mmtlsHandshakeRecordType, uint16(len(payload))), payload...)
	return record, nil
}

func decryptHandshakeRecord(
	record []byte,
	keys connKeys,
	seq uint64,
) ([]byte, error) {
	if len(record) < 5 {
		return nil, fmt.Errorf("handshake record too short")
	}
	payloadLen := binary.BigEndian.Uint16(record[3:5])
	if len(record) != int(payloadLen)+5 {
		return nil, fmt.Errorf("handshake record length mismatch")
	}
	aad := buildAAD(mmtlsHandshakeRecordType, payloadLen, seq)
	nonce, err := gcmNonce(keys.IV, seq)
	if err != nil {
		return nil, err
	}
	return aesGCMDecrypt(keys.Key, nonce, record[5:], aad)
}

func encryptAppRecord(
	outerFrame []byte,
	keys connKeys,
	seq uint64,
	taskID uint32,
	taskType int32,
) ([]byte, error) {
	plain := buildAppPlain(outerFrame, taskID, taskType)
	payloadLen := len(plain) + 16
	if payloadLen > 65535 {
		return nil, fmt.Errorf("longlink record payload exceeds 65535 bytes")
	}
	aad := buildAAD(mmtlsAppRecordType, uint16(payloadLen), seq)
	nonce, err := gcmNonce(keys.IV, seq)
	if err != nil {
		return nil, err
	}
	payload, err := aesGCMEncrypt(keys.Key, nonce, plain, aad)
	if err != nil {
		return nil, err
	}
	record := append(recordHeader(mmtlsAppRecordType, uint16(len(payload))), payload...)
	return record, nil
}

func decryptAppRecord(
	record []byte,
	keys connKeys,
	seq uint64,
) (appPlain, error) {
	if len(record) < 5 {
		return appPlain{}, fmt.Errorf("app record too short")
	}
	recordType := record[0]
	payloadLen := binary.BigEndian.Uint16(record[3:5])
	if len(record) != int(payloadLen)+5 {
		return appPlain{}, fmt.Errorf("app record length mismatch")
	}
	aad := buildAAD(recordType, payloadLen, seq)
	nonce, err := gcmNonce(keys.IV, seq)
	if err != nil {
		return appPlain{}, err
	}
	plain, err := aesGCMDecrypt(keys.Key, nonce, record[5:], aad)
	if err != nil {
		return appPlain{}, err
	}
	return splitAppPlain(plain)
}

func buildAppPlain(
	outerFrame []byte,
	taskID uint32,
	taskType int32,
) []byte {
	totalLen := 16 + len(outerFrame)
	head := make([]byte, 16)
	binary.BigEndian.PutUint32(head[0:4], uint32(totalLen))
	binary.BigEndian.PutUint32(head[4:8], transferWord1)
	binary.BigEndian.PutUint32(head[8:12], taskID)
	binary.BigEndian.PutUint32(head[12:16], uint32(taskType))
	return append(head, outerFrame...)
}

func splitAppPlain(plain []byte) (appPlain, error) {
	if len(plain) < 16 {
		return appPlain{}, fmt.Errorf("app plain too short")
	}
	return appPlain{
		TotalLen:   binary.BigEndian.Uint32(plain[0:4]),
		Word1:      binary.BigEndian.Uint32(plain[4:8]),
		TaskID:     binary.BigEndian.Uint32(plain[8:12]),
		TaskType:   int32(binary.BigEndian.Uint32(plain[12:16])),
		OuterFrame: append([]byte{}, plain[16:]...),
	}, nil
}

func tryDecodeAppRecords(
	records []mmtlsRecord,
	recvKeys connKeys,
) []decodedAppRecord {
	decoded := []decodedAppRecord{}
	for _, record := range records {
		if record.RecordType != mmtlsAppRecordType {
			continue
		}
		for seq := uint64(0); seq <= 16; seq++ {
			plain, err := decryptAppRecord(record.Raw, recvKeys, seq)
			if err == nil {
				decoded = append(decoded, decodedAppRecord{
					Seq: seq,
					App: plain,
				})
				break
			}
		}
	}
	return decoded
}

func extractHybridBodyFromOuter(outer []byte) ([]byte, error) {
	if len(outer) < 8 {
		return append([]byte{}, outer...), nil
	}

	offset := 0
	if outer[offset] == 0x01 {
		offset++
	}
	for {
		tag, next, err := readVarint(outer, offset)
		if err != nil {
			return append([]byte{}, outer...), nil
		}
		offset = next
		if tag == 0 {
			break
		}
		_, next, err = readVarint(outer, offset)
		if err != nil {
			return append([]byte{}, outer...), nil
		}
		offset = next
	}

	for {
		tag, next, err := readVarint(outer, offset)
		if err != nil {
			return append([]byte{}, outer...), nil
		}
		offset = next
		if tag == 0 {
			break
		}
		length, next, err := readVarint(outer, offset)
		if err != nil {
			return append([]byte{}, outer...), nil
		}
		if length > uint64(len(outer)-next) {
			return append([]byte{}, outer...), nil
		}
		offset = next + int(length)
	}

	_, next, err := readVarint(outer, offset)
	if err != nil {
		return append([]byte{}, outer...), nil
	}
	offset = next
	return append([]byte{}, outer[offset:]...), nil
}

func buildAAD(recordType byte, payloadLen uint16, seq uint64) []byte {
	aad := make([]byte, 13)
	binary.BigEndian.PutUint64(aad[0:8], seq)
	aad[8] = recordType
	binary.BigEndian.PutUint16(aad[9:11], mmtlsVersion)
	binary.BigEndian.PutUint16(aad[11:13], payloadLen)
	return aad
}

func recordHeader(recordType byte, payloadLen uint16) []byte {
	header := make([]byte, 5)
	header[0] = recordType
	binary.BigEndian.PutUint16(header[1:3], mmtlsVersion)
	binary.BigEndian.PutUint16(header[3:5], payloadLen)
	return header
}

func writeRecord(conn net.Conn, record []byte, timeout time.Duration) error {
	return writeRecordWithContext(context.Background(), conn, record, timeout)
}

func writeRecordWithContext(
	ctx context.Context,
	conn net.Conn,
	record []byte,
	timeout time.Duration,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(connectionDeadline(ctx, timeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", connectionError(ctx, err))
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	for len(record) > 0 {
		n, err := conn.Write(record)
		if err != nil {
			return fmt.Errorf("write longlink record: %w", connectionError(ctx, err))
		}
		if n == 0 {
			return fmt.Errorf("write longlink record: %w", io.ErrShortWrite)
		}
		record = record[n:]
	}
	return nil
}

func connectionDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && (timeout <= 0 || contextDeadline.Before(deadline)) {
		return contextDeadline
	}
	if timeout <= 0 {
		return time.Time{}
	}
	return deadline
}

func connectionError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

func recvOneRecord(conn net.Conn, timeout time.Duration) (mmtlsRecord, error) {
	return recvOneRecordWithContext(context.Background(), conn, timeout)
}

func recvOneRecordWithContext(ctx context.Context, conn net.Conn, timeout time.Duration) (mmtlsRecord, error) {
	if err := ctx.Err(); err != nil {
		return mmtlsRecord{}, err
	}
	if err := conn.SetReadDeadline(connectionDeadline(ctx, timeout)); err != nil {
		return mmtlsRecord{}, fmt.Errorf("set read deadline: %w", connectionError(ctx, err))
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()

	header := make([]byte, 5)
	if n, err := io.ReadFull(conn, header); err != nil {
		err = connectionError(ctx, err)
		if n > 0 {
			err = errors.Join(errIncompleteMMTLSRecord, err)
		}
		return mmtlsRecord{}, fmt.Errorf("read longlink header: %w", err)
	}

	payloadLen := binary.BigEndian.Uint16(header[3:5])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return mmtlsRecord{}, fmt.Errorf("read longlink payload: %w", errors.Join(errIncompleteMMTLSRecord, connectionError(ctx, err)))
	}

	raw := append(header, payload...)
	return mmtlsRecord{
		RecordType: header[0],
		PayloadLen: payloadLen,
		Raw:        raw,
	}, nil
}

func recvAllRecords(conn net.Conn, timeout time.Duration) ([]mmtlsRecord, error) {
	return recvAllRecordsWithContext(context.Background(), conn, timeout)
}

func recvAllRecordsWithContext(ctx context.Context, conn net.Conn, timeout time.Duration) ([]mmtlsRecord, error) {
	records := []mmtlsRecord{}
	totalBytes := 0
	firstRead := true
	for {
		readTimeout := timeout
		if !firstRead {
			readTimeout = 300 * time.Millisecond
		}
		record, err := recvOneRecordWithContext(ctx, conn, readTimeout)
		if err != nil {
			if len(records) > 0 && isReadTimeout(err) && ctx.Err() == nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, errIncompleteMMTLSRecord) {
				return records, nil
			}
			return nil, err
		}
		records = append(records, record)
		totalBytes += len(record.Raw)
		if totalBytes > 16<<20 {
			return nil, fmt.Errorf("longlink response exceeds 16 MiB")
		}
		firstRead = false
	}
}

func isReadTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
