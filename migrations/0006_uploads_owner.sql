ALTER TABLE uploads ADD COLUMN owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
UPDATE uploads SET owner_id = (SELECT owner_id FROM devices WHERE devices.dongle_id = uploads.dongle_id);
