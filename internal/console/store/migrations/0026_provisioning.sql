-- Provisioning profiles: ordered steps run one after the other on a freshly
-- installed computer. Each save adds a version, never changed afterwards
-- except for its approval (signed envelope, see internal/console/profilereq).
-- Runs track a profile version on one computer, step by step.

CREATE TABLE provisioning_profiles (
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    id          uuid NOT NULL,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE provisioning_profile_versions (
    tenant_id       uuid NOT NULL,
    profile_id      uuid NOT NULL,
    version         integer NOT NULL CHECK (version > 0),
    document        jsonb NOT NULL,
    comment         text NOT NULL DEFAULT '',
    author          text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    envelope        bytea,           -- serialized SignedEnvelope (ProfileRequest), once approved
    max_ttl_seconds integer NOT NULL DEFAULT 0,
    approved_by     text NOT NULL DEFAULT '',
    approved_at     timestamptz,
    expires_at      timestamptz,
    PRIMARY KEY (tenant_id, profile_id, version),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES provisioning_profiles (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE provisioning_runs (
    tenant_id   uuid NOT NULL,
    id          uuid NOT NULL,
    profile_id  uuid NOT NULL,
    version     integer NOT NULL,
    agent_id    uuid NOT NULL,
    state       text NOT NULL,
    step        integer NOT NULL DEFAULT 0,
    jobs        text[] NOT NULL DEFAULT '{}', -- job id per step, '' while not dispatched
    error       text NOT NULL DEFAULT '',
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, profile_id, version)
        REFERENCES provisioning_profile_versions (tenant_id, profile_id, version) ON DELETE CASCADE
);

-- At most one run in progress per computer.
CREATE UNIQUE INDEX provisioning_runs_active ON provisioning_runs (tenant_id, agent_id) WHERE state = 'running';
CREATE INDEX provisioning_runs_profile ON provisioning_runs (tenant_id, profile_id);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['provisioning_profiles', 'provisioning_profile_versions', 'provisioning_runs'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)$p$, t);
    END LOOP;
END $$;
