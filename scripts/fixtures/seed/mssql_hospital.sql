-- Theme: hospital clinical records (SQL Server 2022, database HospitalDB)
IF DB_ID('HospitalDB') IS NULL CREATE DATABASE HospitalDB;
GO
USE HospitalDB;
GO
IF OBJECT_ID('dbo.Prescriptions') IS NOT NULL DROP TABLE dbo.Prescriptions;
IF OBJECT_ID('dbo.Admissions') IS NOT NULL DROP TABLE dbo.Admissions;
IF OBJECT_ID('dbo.Patients') IS NOT NULL DROP TABLE dbo.Patients;
IF OBJECT_ID('dbo.Departments') IS NOT NULL DROP TABLE dbo.Departments;
GO
CREATE TABLE dbo.Patients (
  PatientId INT IDENTITY PRIMARY KEY,
  FullName NVARCHAR(120) NOT NULL,
  DateOfBirth DATE NOT NULL,
  MRN NVARCHAR(20) UNIQUE NOT NULL,
  BloodGroup NVARCHAR(3)
);
CREATE TABLE dbo.Departments (
  DepartmentId INT IDENTITY PRIMARY KEY,
  Name NVARCHAR(80) NOT NULL,
  FloorNumber INT NOT NULL
);
CREATE TABLE dbo.Admissions (
  AdmissionId INT IDENTITY PRIMARY KEY,
  PatientId INT NOT NULL REFERENCES dbo.Patients(PatientId),
  DepartmentId INT NOT NULL REFERENCES dbo.Departments(DepartmentId),
  AdmittedAt DATETIME2 NOT NULL,
  DischargedAt DATETIME2 NULL,
  Diagnosis NVARCHAR(200)
);
CREATE TABLE dbo.Prescriptions (
  PrescriptionId INT IDENTITY PRIMARY KEY,
  AdmissionId INT NOT NULL REFERENCES dbo.Admissions(AdmissionId),
  Drug NVARCHAR(80) NOT NULL,
  Dose NVARCHAR(40) NOT NULL,
  Frequency NVARCHAR(40) NOT NULL
);
GO
INSERT INTO dbo.Patients (FullName, DateOfBirth, MRN, BloodGroup) VALUES
  (N'Harriet Okafor','1961-07-21','MRN-100204','O+'),
  (N'Dmitri Volkov','1983-12-05','MRN-100205','B-'),
  (N'Rosa Delgado','1949-02-14','MRN-100206','A+'),
  (N'Jonas Lindqvist','1998-05-30','MRN-100207','AB+'),
  (N'Amina Sesay','1974-10-11','MRN-100208','O-');
INSERT INTO dbo.Departments (Name, FloorNumber) VALUES
  (N'Cardiology',3),(N'Orthopaedics',2),(N'Neonatology',1),(N'Emergency',0),(N'Oncology',4);
INSERT INTO dbo.Admissions (PatientId, DepartmentId, AdmittedAt, DischargedAt, Diagnosis) VALUES
  (1,1,'2026-08-02T09:15:00','2026-08-09T11:00:00',N'Unstable angina'),
  (2,2,'2026-08-14T14:40:00','2026-08-19T08:30:00',N'Tibial fracture, closed reduction'),
  (3,3,'2026-08-20T03:05:00','2026-08-27T10:15:00',N'Preterm labour, delivered'),
  (4,4,'2026-09-01T22:50:00',NULL,N'Suspected appendicitis, under observation'),
  (5,5,'2026-09-03T07:20:00',NULL,N'Chemotherapy cycle 3'),
  (1,1,'2025-12-11T16:00:00','2025-12-14T09:45:00',N'Atrial fibrillation, rate control');
INSERT INTO dbo.Prescriptions (AdmissionId, Drug, Dose, Frequency) VALUES
  (1,N'Bisoprolol',N'5 mg',N'once daily'),
  (1,N'Aspirin',N'75 mg',N'once daily'),
  (2,N'Morphine sulfate',N'2.5 mg',N'every 6 h as needed'),
  (3,N'Progesterone',N'200 mg',N'every 12 h'),
  (5,N'Paclitaxel',N'175 mg/m2',N'per cycle'),
  (6,N'Apixaban',N'5 mg',N'twice daily');
GO
