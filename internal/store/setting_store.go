package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const bearerTokenSettingKey = "auth.bearer_token"

type SettingStore struct {
	db *sql.DB
}

func NewSettingStore(db *sql.DB) *SettingStore {
	return &SettingStore{db: db}
}

func (s *SettingStore) EnsureBearerToken(ctx context.Context) (string, error) {
	token, err := s.Value(ctx, bearerTokenSettingKey)
	if err == nil && strings.TrimSpace(token) != "" {
		return token, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	token, err = generateBearerToken()
	if err != nil {
		return "", err
	}
	if err := s.Set(ctx, bearerTokenSettingKey, token); err != nil {
		return "", err
	}
	return token, nil
}

func (s *SettingStore) Value(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(
		ctx,
		`select value from service_settings where key = ?`,
		key,
	).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", sql.ErrNoRows
		}
		return "", fmt.Errorf("read setting %q: %w", key, err)
	}
	return value, nil
}

func (s *SettingStore) Set(ctx context.Context, key string, value string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(
		ctx,
		`
		insert into service_settings (key, value, created_at, updated_at)
		values (?, ?, ?, ?)
		on conflict(key) do update set
			value = excluded.value,
			updated_at = excluded.updated_at
		`,
		key,
		value,
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

func generateBearerToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate bearer token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
