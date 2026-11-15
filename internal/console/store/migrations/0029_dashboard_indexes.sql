-- Tenant-wide reads of the dashboard: jobs of the last days and the latest
-- inventory changes of every agent.

CREATE INDEX jobs_created ON jobs (tenant_id, created_at);
CREATE INDEX inventory_changes_at ON inventory_changes (tenant_id, at);
