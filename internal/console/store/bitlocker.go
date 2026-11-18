package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// BitlockerKey is one volume's recovery key, as encrypted by the agent
// itself with the builder's public key (RSA-OAEP/SHA-256). The console
// never holds a plaintext recovery key.
type BitlockerKey struct {
	TenantID       string
	AgentID        string
	Drive          string
	KeyProtectorID string
	Ciphertext     []byte
	UpdatedAt      time.Time
}

// BitlockerKeyStore keeps the encrypted recovery keys reported by agents.
type BitlockerKeyStore interface {
	PutBitlockerKey(ctx context.Context, k BitlockerKey) error
	ListBitlockerKeys(ctx context.Context, tenantID, agentID string) ([]BitlockerKey, error)
	GetBitlockerKey(ctx context.Context, tenantID, agentID, drive string) (BitlockerKey, error)
}

func (m *Memory) PutBitlockerKey(_ context.Context, k BitlockerKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentKey(k.TenantID, k.AgentID)]; !ok {
		return ErrNotFound
	}
	if m.bitlockerKeys == nil {
		m.bitlockerKeys = map[string]BitlockerKey{}
	}
	m.bitlockerKeys[k.TenantID+"/"+k.AgentID+"/"+k.Drive] = k
	return nil
}

func (m *Memory) ListBitlockerKeys(_ context.Context, tenantID, agentID string) ([]BitlockerKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []BitlockerKey
	for _, k := range m.bitlockerKeys {
		if k.TenantID == tenantID && k.AgentID == agentID {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Drive < out[j].Drive })
	return out, nil
}

func (m *Memory) GetBitlockerKey(_ context.Context, tenantID, agentID, drive string) (BitlockerKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.bitlockerKeys[tenantID+"/"+agentID+"/"+drive]
	if !ok {
		return BitlockerKey{}, ErrNotFound
	}
	return k, nil
}

func (p *Postgres) PutBitlockerKey(ctx context.Context, k BitlockerKey) error {
	return p.inTenant(ctx, k.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agent_bitlocker_keys (tenant_id, agent_id, drive, key_protector_id, ciphertext, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id, agent_id, drive) DO UPDATE SET
			key_protector_id = EXCLUDED.key_protector_id, ciphertext = EXCLUDED.ciphertext, updated_at = EXCLUDED.updated_at`,
			k.TenantID, k.AgentID, k.Drive, k.KeyProtectorID, k.Ciphertext, k.UpdatedAt)
		return err
	})
}

func (p *Postgres) ListBitlockerKeys(ctx context.Context, tenantID, agentID string) ([]BitlockerKey, error) {
	var out []BitlockerKey
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT drive, key_protector_id, ciphertext, updated_at FROM agent_bitlocker_keys
			WHERE agent_id = $1 ORDER BY drive`, agentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			k := BitlockerKey{TenantID: tenantID, AgentID: agentID}
			if err := rows.Scan(&k.Drive, &k.KeyProtectorID, &k.Ciphertext, &k.UpdatedAt); err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) GetBitlockerKey(ctx context.Context, tenantID, agentID, drive string) (BitlockerKey, error) {
	var k BitlockerKey
	err := p.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		k, err = scanBitlockerKey(tx.QueryRow(ctx, `SELECT drive, key_protector_id, ciphertext, updated_at
			FROM agent_bitlocker_keys WHERE agent_id = $1 AND drive = $2`, agentID, drive))
		return err
	})
	k.TenantID, k.AgentID = tenantID, agentID
	if errors.Is(err, pgx.ErrNoRows) {
		return BitlockerKey{}, ErrNotFound
	}
	return k, err
}

func scanBitlockerKey(row pgx.Row) (BitlockerKey, error) {
	var k BitlockerKey
	err := row.Scan(&k.Drive, &k.KeyProtectorID, &k.Ciphertext, &k.UpdatedAt)
	return k, err
}
