-- BitLocker recovery keys, encrypted on the endpoint itself with the
-- builder's public key (RSA-OAEP/SHA-256): the console only ever holds
-- ciphertext. Decrypting one happens only in the builder, on demand, after
-- an operator gives the signing passphrase.
CREATE TABLE agent_bitlocker_keys (
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    agent_id         uuid NOT NULL,
    drive            text NOT NULL,
    key_protector_id text NOT NULL,
    ciphertext       bytea NOT NULL,
    updated_at       timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, drive),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

ALTER TABLE agent_bitlocker_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_bitlocker_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_bitlocker_keys
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
