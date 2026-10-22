package db

import (
	"context"
	"database/sql"
	"fmt"
)

func initSchema(ctx context.Context, handle *sql.DB) error {
	statements := []string{
		`
		create table if not exists service_settings (
			key text primary key,
			value text not null,
			created_at text not null,
			updated_at text not null
		)
		`,
		`
		create table if not exists accounts (
			id integer primary key autoincrement,
			unionid text not null unique,
			openid text not null,
			guid text not null,
			login_type text not null,
			access_token text not null,
			refresh_token text not null,
			wx_code text not null default '',
			state text not null default '',
			saved_session_json text not null,
			raw_protocol_tdi_json text not null default '{}',
			device_id_b64 text not null default '',
			app_device_id text not null default '',
			username text not null default '',
			uin text not null default '',
			autoauth_key_b64 text not null default '',
			autoauth_enc_key_b64 text not null default '',
			created_at text not null,
			updated_at text not null
		)
		`,
		`
		create table if not exists scan_sessions (
			id integer primary key autoincrement,
			status text not null,
			guid text not null,
			state text not null,
			uuid text not null,
			qr_url text not null,
			last_errcode text not null default '',
			wx_code text not null default '',
			openid text not null default '',
			unionid text not null default '',
			account_id integer,
			error_text text not null default '',
			created_at text not null,
			updated_at text not null,
			foreign key (account_id) references accounts(id) on delete set null
		)
		`,
	}

	for _, statement := range statements {
		if _, err := handle.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}

	return nil
}
