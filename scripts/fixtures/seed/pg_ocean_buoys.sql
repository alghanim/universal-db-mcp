-- Theme: oceanographic buoy network (PostgreSQL, schema ocean)
CREATE SCHEMA IF NOT EXISTS ocean;
CREATE TABLE IF NOT EXISTS ocean.buoys (
  buoy_id serial PRIMARY KEY,
  callsign VARCHAR(12) UNIQUE NOT NULL,
  region VARCHAR(60) NOT NULL,
  lat DOUBLE PRECISION NOT NULL,
  lon DOUBLE PRECISION NOT NULL,
  deployed_on DATE NOT NULL
);
CREATE TABLE IF NOT EXISTS ocean.readings (
  reading_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  buoy_id int NOT NULL REFERENCES ocean.buoys(buoy_id),
  recorded_at timestamptz NOT NULL,
  sea_temp_c NUMERIC(4,1) NOT NULL,
  wave_height_m NUMERIC(4,2) NOT NULL
);
TRUNCATE ocean.readings, ocean.buoys RESTART IDENTITY CASCADE;
INSERT INTO ocean.buoys (callsign, region, lat, lon, deployed_on) VALUES
  ('MB-ALPHA','Arabian Sea',22.4111,59.8221,'2025-04-02'),
  ('MB-BRAVO','Gulf of Oman',24.4111,57.8221,'2025-04-18'),
  ('MB-CHARLIE','Red Sea',20.1222,38.8333,'2025-06-30');
INSERT INTO ocean.readings (buoy_id, recorded_at, sea_temp_c, wave_height_m)
SELECT 1 + (n % 3),
       timestamptz '2026-09-01 00:00:00+04' + make_interval(hours => n),
       round((29.1 + ((n * 37) % 41) / 10.0)::numeric, 1),
       round(((0.4 + ((n * 53) % 130) / 100.0))::numeric, 2)
FROM generate_series(0, 59) AS n;
