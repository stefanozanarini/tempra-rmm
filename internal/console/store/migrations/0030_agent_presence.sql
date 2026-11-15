-- Availability: every 15 minutes the console samples whether each approved
-- agent is online; one row per agent and day (UTC) counts the samples and
-- those online, for the availability on Reporting → Dashboard.

CREATE TABLE agent_presence (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    agent_id  uuid NOT NULL,
    day       date NOT NULL,
    samples   integer NOT NULL,
    online    integer NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, day)
);

CREATE INDEX agent_presence_day ON agent_presence (tenant_id, day);

ALTER TABLE agent_presence ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_presence FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_presence
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
