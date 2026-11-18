-- Whether the agent's last inventory reported at least one battery, so the
-- agents list can show a laptop icon instead of a desktop one (servers are
-- already told apart by the agent's OS family, not by this column).
ALTER TABLE inventories ADD COLUMN has_battery boolean NOT NULL DEFAULT false;
