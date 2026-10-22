package tdi

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	ilinkAppID            = "ilinkapp_060000b7b93f6c"
	productID             = "0"
	defaultUIN            = "0"
	defaultLoginType      = "4"
	defaultLoginScene     = "1901"
	defaultAppSessionType = "0"
)

type Record struct {
	Username           string
	DeviceIDB64        string
	AppDeviceID        string
	UIN                string
	AutoAuthKeyB64     string
	AutoAuthEncKeyB64  string
	RawProtocolTDIJSON string
}

func BuildFileContent(record Record, workDir string) string {
	lines := []string{
		"kTdiKeyIlinkAppId=" + ilinkAppID,
		"kTdiKeyIlinkProductId=" + productID,
		"kTdiKeyUin=" + valueOrDefault(record.UIN, defaultUIN),
		"kTdiKeyUsername=" + record.Username,
		"kTdiKeyIlinkAppSessionType=" + defaultAppSessionType,
		"kTdiKeyLoginScene=" + defaultLoginScene,
		"kTdiKeyLoginType=" + defaultLoginType,
		"kTdiKeyDeviceId=" + record.DeviceIDB64,
		"kTdiKeyWorkDirectory=" + filepath.ToSlash(workDir),
	}

	if strings.TrimSpace(record.AutoAuthKeyB64) != "" {
		lines = append(lines, "kTdiKeyAutoauthKey="+record.AutoAuthKeyB64)
	}
	if strings.TrimSpace(record.AutoAuthEncKeyB64) != "" {
		lines = append(lines, "kTdiKeyAutoauthEncKey="+record.AutoAuthEncKeyB64)
	}

	return strings.Join(lines, "\n") + "\n"
}

func MergeProtocolTDI(raw string, record Record) (map[string]any, error) {
	protocolTDI := map[string]any{}
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &protocolTDI); err != nil {
			return nil, fmt.Errorf("decode protocol tdi json: %w", err)
		}
	}

	if record.Username != "" {
		protocolTDI["username"] = record.Username
	}
	if record.UIN != "" {
		protocolTDI["uin"] = record.UIN
	}
	if record.AutoAuthKeyB64 != "" {
		protocolTDI["autoauthKeyB64"] = record.AutoAuthKeyB64
	}
	if record.AutoAuthEncKeyB64 != "" {
		protocolTDI["autoauthEncKeyB64"] = record.AutoAuthEncKeyB64
		protocolTDI["sessionKeyB64"] = record.AutoAuthEncKeyB64
	}

	return protocolTDI, nil
}

func valueOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
