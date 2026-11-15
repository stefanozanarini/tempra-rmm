-- Limits of operators to some sites or computer groups. The roles come from
-- Entra app roles; a scope narrows the computers an operator acts on. The
-- subject is the object id of a user or of an Entra security group (groups
-- claim).

CREATE TABLE operator_scopes (
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    subject_oid  uuid NOT NULL,
    subject_name text NOT NULL,
    site_ids     uuid[] NOT NULL DEFAULT '{}',
    group_ids    uuid[] NOT NULL DEFAULT '{}',
    updated_by   text NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject_oid)
);

ALTER TABLE operator_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON operator_scopes
    USING (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('openrmm.tenant_id', true), '')::uuid);
