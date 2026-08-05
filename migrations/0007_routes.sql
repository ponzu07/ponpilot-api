ALTER TABLE devices ADD COLUMN alias TEXT;

CREATE TABLE routes (
  dongle_id  TEXT NOT NULL REFERENCES devices(dongle_id) ON DELETE CASCADE,
  route_name TEXT NOT NULL,
  owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  is_public  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (dongle_id, route_name, owner_id)
);
