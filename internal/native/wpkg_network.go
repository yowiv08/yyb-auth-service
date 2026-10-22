package native

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"yyb-auth-service/internal/session"
)

const (
	IlinkAppID            = "ilinkapp_060000b7b93f6c"
	LonglinkDefaultPort   = 5000
	ShortcloudDefaultPort = 80
	LongcloudHostname     = "longcloud.weixin.com"
	ShortcloudHostname    = "shortcloud.weixin.com"
)

type HostIPEntry struct {
	IDCType int    `json:"idcType"`
	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
}

type HostGroup struct {
	Hostname string        `json:"hostname"`
	IPs      []HostIPEntry `json:"ips"`
}

type HostTables struct {
	Strategy   int         `json:"strategy"`
	Groups     []HostGroup `json:"groups,omitempty"`
	Longcloud  []HostGroup `json:"longcloud,omitempty"`
	Shortcloud []HostGroup `json:"shortcloud,omitempty"`
}

type LonglinkEndpoint struct {
	Host     string
	Port     int
	Source   string
	Hostname string
}

type LonglinkProfile struct {
	UIN        uint64
	IlinkAppID string
	Field27    []byte
}

type LonglinkPack struct {
	IntTags           map[int]int64
	StrTags           map[int][]byte
	DeclaredHeaderLen int
	ActualHeaderLen   int
	HeaderLenMatches  bool
	Body              []byte
}

func parseNetworkSectHosts(netRaw []byte) (HostTables, error) {
	if len(netRaw) == 0 {
		return HostTables{}, nil
	}

	fields, err := pbDecode(netRaw)
	if err != nil {
		return HostTables{}, fmt.Errorf("decode network sect: %w", err)
	}

	result := HostTables{}
	if strategy, ok := firstVarint(fields, 2); ok {
		result.Strategy = int(strategy)
	}

	for _, value := range fields[1] {
		group, err := parseHostGroup(value.Bytes)
		if err != nil {
			return HostTables{}, err
		}
		result.Groups = append(result.Groups, group)
		if strings.Contains(group.Hostname, "longcloud") {
			result.Longcloud = append(result.Longcloud, group)
		}
		if strings.Contains(group.Hostname, "shortcloud") {
			result.Shortcloud = append(result.Shortcloud, group)
		}
	}

	return result, nil
}

func parseHostGroup(raw []byte) (HostGroup, error) {
	fields, err := pbDecode(raw)
	if err != nil {
		return HostGroup{}, fmt.Errorf("decode host group: %w", err)
	}

	group := HostGroup{
		Hostname: decodeUTF8(firstNonNil(firstBytes(fields, 1), firstBytes(fields, 2))),
	}
	for _, value := range fields[3] {
		entry, err := parseIPEntry(value.Bytes)
		if err != nil {
			return HostGroup{}, err
		}
		group.IPs = append(group.IPs, entry)
	}

	return group, nil
}

func parseIPEntry(raw []byte) (HostIPEntry, error) {
	fields, err := pbDecode(raw)
	if err != nil {
		return HostIPEntry{}, fmt.Errorf("decode ip entry: %w", err)
	}

	entry := HostIPEntry{
		IPv4: decodeUTF8(firstBytes(fields, 2)),
		IPv6: decodeUTF8(firstBytes(fields, 3)),
	}
	if idcType, ok := firstVarint(fields, 1); ok {
		entry.IDCType = int(idcType)
	}
	return entry, nil
}

func resolveLonglinkEndpoint(
	ctx context.Context,
	saved session.SavedSession,
) (LonglinkEndpoint, error) {
	if host := strings.TrimSpace(protocolTDIString(saved.ProtocolTDI, "longcloudHost")); host != "" {
		return LonglinkEndpoint{
			Host:     host,
			Port:     LonglinkDefaultPort,
			Source:   "protocol_tdi",
			Hostname: LongcloudHostname,
		}, nil
	}

	if networkSectB64 := protocolTDIString(saved.ProtocolTDI, "networkSectB64"); networkSectB64 != "" {
		netRaw, err := base64.StdEncoding.DecodeString(networkSectB64)
		if err == nil {
			hosts, parseErr := parseNetworkSectHosts(netRaw)
			if parseErr == nil {
				if ipv4 := pickIPv4(flattenIPs(hosts.Longcloud)); ipv4 != "" {
					return LonglinkEndpoint{
						Host:     ipv4,
						Port:     LonglinkDefaultPort,
						Source:   "network_sect",
						Hostname: LongcloudHostname,
					}, nil
				}
			}
		}
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, LongcloudHostname)
	if err == nil {
		for _, ip := range ips {
			if ipv4 := ip.IP.To4(); ipv4 != nil {
				return LonglinkEndpoint{
					Host:     ipv4.String(),
					Port:     LonglinkDefaultPort,
					Source:   "dns",
					Hostname: LongcloudHostname,
				}, nil
			}
		}
	}

	return LonglinkEndpoint{
		Host:     "117.89.177.75",
		Port:     LonglinkDefaultPort,
		Source:   "fallback-cp-default",
		Hostname: LongcloudHostname,
	}, nil
}

func resolveShortcloudEndpoint(
	ctx context.Context,
	saved session.SavedSession,
) (LonglinkEndpoint, error) {
	if networkSectB64 := protocolTDIString(saved.ProtocolTDI, "networkSectB64"); networkSectB64 != "" {
		netRaw, err := base64.StdEncoding.DecodeString(networkSectB64)
		if err == nil {
			hosts, parseErr := parseNetworkSectHosts(netRaw)
			if parseErr == nil {
				if ipv4 := pickIPv4(flattenIPs(hosts.Shortcloud)); ipv4 != "" {
					return LonglinkEndpoint{
						Host:     ipv4,
						Port:     ShortcloudDefaultPort,
						Source:   "network_sect",
						Hostname: ShortcloudHostname,
					}, nil
				}
			}
		}
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, ShortcloudHostname)
	if err == nil {
		for _, ip := range ips {
			if ipv4 := ip.IP.To4(); ipv4 != nil {
				return LonglinkEndpoint{
					Host:     ipv4.String(),
					Port:     ShortcloudDefaultPort,
					Source:   "dns",
					Hostname: ShortcloudHostname,
				}, nil
			}
		}
	}

	return LonglinkEndpoint{
		Host:     "101.91.29.36",
		Port:     ShortcloudDefaultPort,
		Source:   "fallback-cp-default",
		Hostname: ShortcloudHostname,
	}, nil
}

func flattenIPs(groups []HostGroup) []HostIPEntry {
	entries := []HostIPEntry{}
	for _, group := range groups {
		entries = append(entries, group.IPs...)
	}
	return entries
}

func pickIPv4(entries []HostIPEntry) string {
	for _, entry := range entries {
		if strings.TrimSpace(entry.IPv4) != "" {
			return entry.IPv4
		}
	}
	return ""
}

func buildLonglinkPackHeader(
	profile LonglinkProfile,
	identityMode string,
) ([]byte, error) {
	if identityMode != "zero" && identityMode != "account" {
		return nil, fmt.Errorf("unsupported longlink identity mode %q", identityMode)
	}

	uin := uint64(0)
	field25 := uint64(17)
	field27 := []byte{}
	if identityMode == "account" {
		uin = profile.UIN
		field25 = 16
		field27 = profile.Field27
	}

	scalarFields := [][2]uint64{
		{1, 1},
		{2, uin},
		{3, 0},
		{4, 0},
		{5, 0x80101},
		{6, 11},
		{7, 0},
		{8, 0},
		{9, 0},
		{10, 1},
		{11, 0},
		{12, 0},
		{13, 0},
		{17, 0},
		{18, 1},
		{20, 1504},
		{21, 0},
		{22, uin},
		{23, 0},
		{25, field25},
		{26, 4},
		{28, 1},
		{29, 1},
		{30, 0},
	}

	bytesFields := map[int][]byte{
		14: {},
		24: []byte(firstNonEmpty(profile.IlinkAppID, IlinkAppID)),
		27: field27,
	}

	content := []byte{0x01}
	for _, field := range scalarFields {
		content = append(content, writeVarint(field[0])...)
		content = append(content, writeVarint(field[1])...)
	}
	content = append(content, 0x00)
	for _, fieldID := range []int{14, 24, 27} {
		value := bytesFields[fieldID]
		content = append(content, writeVarint(uint64(fieldID))...)
		content = append(content, writeVarint(uint64(len(value)))...)
		content = append(content, value...)
	}
	content = append(content, 0x00)
	content = append(content, writeVarint(uint64(len(content)))...)
	return content, nil
}

func parseLonglinkPackHeader(buf []byte) (LonglinkPack, error) {
	if len(buf) == 0 {
		return LonglinkPack{}, fmt.Errorf("empty longlink pack")
	}
	if buf[0] != 0x01 {
		return LonglinkPack{}, fmt.Errorf("unexpected pack version byte 0x%x", buf[0])
	}

	offset := 1
	intTags := map[int]int64{}
	for offset < len(buf) {
		tag, next, err := readVarint(buf, offset)
		if err != nil {
			return LonglinkPack{}, fmt.Errorf("decode longlink int tag: %w", err)
		}
		offset = next
		if tag == 0 {
			break
		}

		value, cursor, err := readVarint(buf, offset)
		if err != nil {
			return LonglinkPack{}, fmt.Errorf("decode longlink int value: %w", err)
		}
		offset = cursor
		intTags[int(tag)] = int64(value)
	}

	strTags := map[int][]byte{}
	for offset < len(buf) {
		tag, next, err := readVarint(buf, offset)
		if err != nil {
			return LonglinkPack{}, fmt.Errorf("decode longlink bytes tag: %w", err)
		}
		offset = next
		if tag == 0 {
			break
		}

		length, cursor, err := readVarint(buf, offset)
		if err != nil {
			return LonglinkPack{}, fmt.Errorf("decode longlink bytes length: %w", err)
		}
		offset = cursor
		if length > uint64(len(buf)-offset) {
			return LonglinkPack{}, fmt.Errorf("truncated longlink bytes field %d", tag)
		}
		end := offset + int(length)

		strTags[int(tag)] = append([]byte{}, buf[offset:end]...)
		offset = end
	}

	trailerOffset := offset
	declaredHeaderLen, next, err := readVarint(buf, offset)
	if err != nil {
		return LonglinkPack{}, fmt.Errorf("decode longlink trailer: %w", err)
	}
	if declaredHeaderLen > uint64(len(buf)) {
		return LonglinkPack{}, fmt.Errorf("longlink header length exceeds packet size")
	}
	offset = next

	return LonglinkPack{
		IntTags:           intTags,
		StrTags:           strTags,
		DeclaredHeaderLen: int(declaredHeaderLen),
		ActualHeaderLen:   trailerOffset,
		HeaderLenMatches:  int(declaredHeaderLen) == trailerOffset,
		Body:              append([]byte{}, buf[offset:]...),
	}, nil
}

func decodeUTF8(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return string(raw)
}

func firstNonNil(values ...[]byte) []byte {
	for _, value := range values {
		if len(value) > 0 {
			return value
		}
	}
	return nil
}
