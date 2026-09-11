-- Theme: telecom call data records (ClickHouse, database telecom)
CREATE DATABASE IF NOT EXISTS telecom;
CREATE TABLE IF NOT EXISTS telecom.subscribers (
  subscriber_id UInt64,
  msisdn String,
  full_name String,
  tariff String,
  activated Date
) ENGINE MergeTree ORDER BY subscriber_id;
CREATE TABLE IF NOT EXISTS telecom.cell_towers (
  cell_id UInt32,
  site_name String,
  district String,
  lat Float64,
  lon Float64,
  bands Array(String)
) ENGINE MergeTree ORDER BY cell_id;
CREATE TABLE IF NOT EXISTS telecom.cdr (
  call_id UUID,
  started_at DateTime,
  duration_sec UInt32,
  caller_msisdn String,
  callee_msisdn String,
  cell_id UInt32,
  direction Enum8('outgoing' = 1, 'incoming' = 2),
  roaming Bool,
  cost Decimal(10, 4)
) ENGINE MergeTree PARTITION BY toYYYYMM(started_at) ORDER BY (started_at, caller_msisdn);
TRUNCATE TABLE telecom.cdr;
INSERT INTO telecom.subscribers VALUES
  (1,'971501000001','Aisha Kareem','postpaid_flex','2023-01-15'),
  (2,'971501000002','Bogdan Ilic','prepaid_go','2024-06-02'),
  (3,'971501000003','Chen Wei','postpaid_max','2022-11-30'),
  (4,'971501000004','Divya Menon','prepaid_go','2025-03-21'),
  (5,'971501000005','Emeka Obi','postpaid_flex','2021-08-09');
INSERT INTO telecom.cell_towers VALUES
  (101,'Marina Torre','JLT',25.0715,55.1377,['n78','n41']),
  (102,'Dune Ridge','Al Marmoom',24.8522,55.3311,['b3','b7']),
  (103,'Creek Exchange','Deira',25.2697,55.3095,['n78','b1','b3']),
  (104,'Oasis Node','Al Ain',24.2075,55.7447,['b7','b28']),
  (105,'Harbor Relay','Jebel Ali',24.9852,55.1081,['n41','b7']);
INSERT INTO telecom.cdr
SELECT
  toUUID(lower(substring(hex(MD5(toString(number))), 1, 8) || '-' || substring(hex(MD5(toString(number+1))), 1, 4) || '-4' || substring(hex(MD5(toString(number+2))), 1, 3) || '-a' || substring(hex(MD5(toString(number+3))), 1, 3) || '-' || substring(hex(MD5(toString(number+4))), 1, 12))) AS call_id,
  toDateTime('2026-08-01 00:00:00') + toIntervalSecond(number % 2500000) AS started_at,
  5 + (number * 7919) % 1800 AS duration_sec,
  '97150100000' || toString(1 + number % 5) AS caller_msisdn,
  '97150200000' || toString(1 + (number * 13) % 90) AS callee_msisdn,
  101 + number % 5 AS cell_id,
  if(number % 3 = 0, 'incoming', 'outgoing') AS direction,
  number % 11 = 0 AS roaming,
  round((0.02 + ((number * 37) % 400) / 10000.0) * (5 + (number * 7919) % 1800), 4) AS cost
FROM numbers(250000);
