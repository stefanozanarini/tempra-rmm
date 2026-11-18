package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

func (m *Memory) GetConsoleSettings(context.Context) (ConsoleSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.consoleSettings, nil
}

func (m *Memory) SetMSPMode(_ context.Context, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consoleSettings.MSPMode = on
	return nil
}

func (m *Memory) SetBitlockerPublicKey(_ context.Context, pem string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consoleSettings.BitlockerPublicKeyPEM = pem
	return nil
}

func (p *Postgres) GetConsoleSettings(ctx context.Context) (ConsoleSettings, error) {
	var c ConsoleSettings
	err := p.pool.QueryRow(ctx, `SELECT msp_mode, bitlocker_public_key FROM console_settings`).Scan(&c.MSPMode, &c.BitlockerPublicKeyPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	return c, err
}

func (p *Postgres) SetMSPMode(ctx context.Context, on bool) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO console_settings (msp_mode) VALUES ($1)
		ON CONFLICT (singleton) DO UPDATE SET msp_mode = EXCLUDED.msp_mode`, on)
	return err
}

func (p *Postgres) SetBitlockerPublicKey(ctx context.Context, pem string) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO console_settings (singleton, bitlocker_public_key) VALUES (true, $1)
		ON CONFLICT (singleton) DO UPDATE SET bitlocker_public_key = EXCLUDED.bitlocker_public_key`, pem)
	return err
}
