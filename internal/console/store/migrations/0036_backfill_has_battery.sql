-- 0035 added has_battery defaulting to false for every existing row; back-fill
-- it right away from the inventory already on file, instead of waiting for
-- each agent's next scheduled inventory collection (up to 24h).
UPDATE inventories SET has_battery = true
WHERE jsonb_array_length(data->'batteries') > 0;
