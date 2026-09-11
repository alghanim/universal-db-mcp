-- Theme: specialty coffee roastery (MySQL, database testdb)
CREATE TABLE IF NOT EXISTS roastery_batches (
  batch_id INT AUTO_INCREMENT PRIMARY KEY,
  bean_origin VARCHAR(80) NOT NULL,
  process VARCHAR(40) NOT NULL,
  roast_level VARCHAR(20) NOT NULL,
  weight_kg DECIMAL(6,2) NOT NULL,
  roasted_on DATE NOT NULL
);
CREATE TABLE IF NOT EXISTS cuppings (
  cupping_id INT AUTO_INCREMENT PRIMARY KEY,
  batch_id INT NOT NULL,
  taster VARCHAR(60) NOT NULL,
  score DECIMAL(4,2) NOT NULL,
  notes VARCHAR(200),
  FOREIGN KEY (batch_id) REFERENCES roastery_batches(batch_id)
);
SET FOREIGN_KEY_CHECKS=0; TRUNCATE cuppings; TRUNCATE roastery_batches; SET FOREIGN_KEY_CHECKS=1;
INSERT INTO roastery_batches (bean_origin, process, roast_level, weight_kg, roasted_on) VALUES
  ('Yirgacheffe, Ethiopia','washed','light',12.50,'2026-08-30'),
  ('Huila, Colombia','honey','medium',18.00,'2026-09-01'),
  ('Nyeri, Kenya AA','washed','light',9.75,'2026-09-03'),
  ('Mandheling, Sumatra','wet-hulled','dark',22.25,'2026-09-05'),
  ('Boquete, Panama','natural','medium',6.40,'2026-09-06');
INSERT INTO cuppings (batch_id, taster, score, notes) VALUES
  (1,'R. Haddad',88.50,'jasmine, bergamot, crisp acidity'),
  (1,'T. Nakamura',87.25,'black tea finish'),
  (2,'R. Haddad',85.75,'panela sweetness, stone fruit'),
  (3,'L. Osei',91.00,'blackcurrant, tomato leaf'),
  (4,'T. Nakamura',82.50,'cedar, heavy body, low acid'),
  (5,'L. Osei',89.25,'strawberry, fermented, winey');
