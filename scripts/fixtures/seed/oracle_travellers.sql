-- Theme: international air travellers (Oracle Free, schema TRAVEL)
WHENEVER SQLERROR EXIT FAILURE
CONNECT system/"UdbmcpOracle_23ai"@localhost:1521/FREEPDB1
BEGIN
  EXECUTE IMMEDIATE 'CREATE USER travel IDENTIFIED BY "Travel_Pass_1"';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -1920 THEN RAISE; END IF;
END;
/
GRANT CONNECT, RESOURCE TO travel;
ALTER USER travel QUOTA UNLIMITED ON USERS;
CONNECT travel/"Travel_Pass_1"@localhost:1521/FREEPDB1
CREATE TABLE travellers (
  traveller_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  full_name VARCHAR2(120) NOT NULL,
  nationality VARCHAR2(60) NOT NULL,
  passport_no VARCHAR2(20) UNIQUE NOT NULL,
  frequent_flyer_tier VARCHAR2(20)
);
CREATE TABLE flights (
  flight_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  carrier VARCHAR2(10) NOT NULL,
  flight_no VARCHAR2(10) NOT NULL,
  origin_airport VARCHAR2(3) NOT NULL,
  dest_airport VARCHAR2(3) NOT NULL,
  scheduled_depart TIMESTAMP NOT NULL,
  aircraft VARCHAR2(40)
);
CREATE TABLE bookings (
  booking_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  traveller_id NUMBER NOT NULL REFERENCES travellers(traveller_id),
  flight_id NUMBER NOT NULL REFERENCES flights(flight_id),
  cabin_class VARCHAR2(20) NOT NULL,
  fare_amount NUMBER(10,2) NOT NULL,
  booked_at TIMESTAMP DEFAULT SYSTIMESTAMP
);
CREATE TABLE boarding_passes (
  pass_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  booking_id NUMBER NOT NULL REFERENCES bookings(booking_id),
  seat VARCHAR2(6) NOT NULL,
  gate VARCHAR2(5),
  issued_at TIMESTAMP DEFAULT SYSTIMESTAMP
);
INSERT INTO travellers (full_name, nationality, passport_no, frequent_flyer_tier) VALUES
  ('Amara Diallo','Senegalese','SN8842130','gold'),
  ('Kenji Watanabe','Japanese','JP7712094','platinum'),
  ('Ingrid Solberg','Norwegian','NO5530118',NULL),
  ('Tomas Herrera','Chilean','CL9902873','silver'),
  ('Leilani Kealoha','American','US4471056','gold'),
  ('Farid Al-Rashid','Emirati','AE3305677','platinum'),
  ('Marta Kowalczyk','Polish','PL6620913',NULL),
  ('Sipho Ndlovu','South African','ZA2147809','silver');
INSERT INTO flights (carrier, flight_no, origin_airport, dest_airport, scheduled_depart, aircraft) VALUES
  ('ET','ET910','ADD','NBO',TIMESTAMP '2026-09-15 08:40:00','Boeing 787-8'),
  ('SQ','SQ317','SIN','LHR',TIMESTAMP '2026-09-16 23:15:00','Airbus A380-800'),
  ('EK','EK202','DXB','JFK',TIMESTAMP '2026-09-17 02:30:00','Boeing 777-300ER'),
  ('LA','LA705','SCL','IPC',TIMESTAMP '2026-09-18 09:55:00','Boeing 787-9'),
  ('JL','JL62','HND','SFO',TIMESTAMP '2026-09-19 17:20:00','Boeing 777-300ER'),
  ('QF','QF9','MEL','PER',TIMESTAMP '2026-09-20 06:05:00','Airbus A330-300');
INSERT INTO bookings (traveller_id, flight_id, cabin_class, fare_amount) VALUES
  (1,1,'economy',612.40),(2,2,'business',3890.00),(3,3,'economy',845.75),
  (4,4,'premium_economy',1780.10),(5,5,'business',4120.60),(6,3,'first',7625.00),
  (7,1,'economy',598.90),(8,6,'economy',242.35),(1,5,'economy',1180.00),
  (2,3,'business',5210.25),(5,2,'economy',1099.99),(3,4,'economy',923.40),
  (6,1,'business',2975.00),(7,2,'premium_economy',1642.80),(8,5,'economy',1015.55),
  (4,2,'economy',1344.70),(1,3,'business',4480.00),(9-8,6,'economy',199.00);
COMMIT;
EXIT SUCCESS
