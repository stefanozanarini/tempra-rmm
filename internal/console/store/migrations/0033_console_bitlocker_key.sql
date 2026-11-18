-- The public half of the builder's BitLocker encryption key (not a secret:
-- the private half never leaves the builder's encrypted state), cached here
-- so core can hand it to agents without ever talking to the builder.
ALTER TABLE console_settings ADD COLUMN bitlocker_public_key text NOT NULL DEFAULT '';
