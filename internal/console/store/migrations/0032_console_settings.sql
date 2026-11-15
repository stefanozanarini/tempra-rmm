-- Console-wide settings, one row (like federation_uplink). Today just the
-- MSP mode flag; more console-wide switches can join this table later.
CREATE TABLE console_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    msp_mode  boolean NOT NULL DEFAULT false
);
