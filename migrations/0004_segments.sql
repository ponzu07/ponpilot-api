CREATE TABLE segments (
  dongle_id    TEXT NOT NULL REFERENCES devices(dongle_id) ON DELETE CASCADE,
  route_name   TEXT NOT NULL,
  segment      INTEGER NOT NULL,
  claimed_at   INTEGER NOT NULL,
  parsed_at    INTEGER,
  start_millis INTEGER,
  start_offset INTEGER,
  end_offset   INTEGER,
  distance_m   REAL,
  first_lat    REAL,
  first_lng    REAL,
  last_lat     REAL,
  last_lng     REAL,
  coords       TEXT,
  events       TEXT,
  PRIMARY KEY (dongle_id, route_name, segment)
);
