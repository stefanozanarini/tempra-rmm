-- Daily counts of the vulnerabilities affecting a tenant's computers, by
-- severity, for the trend on Security → Dashboard. The row of the day is
-- overwritten each time the CVEs are matched again.

CREATE TABLE vuln_history (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    day        date NOT NULL,
    counts     jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, day)
);
