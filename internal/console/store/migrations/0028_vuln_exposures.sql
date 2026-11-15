-- Each CVE affecting a computer, from when it was first found to when it
-- went away, for the time to fix on Security → Dashboard. baseline: found
-- at the first recording of the tenant, so its real age is unknown;
-- removed: closed because the computer left (revoked, deleted), not fixed.

CREATE TABLE vuln_exposures (
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    agent_id    uuid NOT NULL,
    cve         text NOT NULL,
    severity    text NOT NULL,
    first_seen  timestamptz NOT NULL,
    resolved_at timestamptz,
    baseline    boolean NOT NULL DEFAULT false,
    removed     boolean NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX vuln_exposures_open ON vuln_exposures (tenant_id, agent_id, cve) WHERE resolved_at IS NULL;
CREATE INDEX vuln_exposures_first ON vuln_exposures (tenant_id, first_seen);
CREATE INDEX vuln_exposures_resolved ON vuln_exposures (tenant_id, resolved_at);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['vuln_exposures', 'vuln_history'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)$p$, t);
    END LOOP;
END $$;
