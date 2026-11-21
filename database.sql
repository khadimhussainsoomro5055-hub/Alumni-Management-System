CREATE DATABASE IF NOT EXISTS alumni_system;
USE alumni_system;

CREATE TABLE IF NOT EXISTS alumni (
  id INT AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(150) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  phone VARCHAR(30),
  gender VARCHAR(20),
  date_of_birth DATE,
  student_id VARCHAR(60) UNIQUE,
  degree VARCHAR(150),
  department VARCHAR(150) NOT NULL,
  graduation_year YEAR NOT NULL,
  current_job VARCHAR(150),
  company VARCHAR(150),
  city VARCHAR(100),
  country VARCHAR(100) DEFAULT 'Pakistan',
  address TEXT,
  password VARCHAR(255) NOT NULL,
  profile_photo VARCHAR(255),
  role ENUM('alumni', 'admin') NOT NULL DEFAULT 'alumni',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Migration for an older alumni table that was created without profile_photo.
SET @column_exists = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'alumni'
    AND COLUMN_NAME = 'profile_photo'
);
SET @sql = IF(
  @column_exists = 0,
  'ALTER TABLE alumni ADD COLUMN profile_photo VARCHAR(255) NULL',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  event_date DATETIME NOT NULL,
  location VARCHAR(200) NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS jobs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  company VARCHAR(200) NOT NULL,
  location VARCHAR(150),
  description TEXT,
  posted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO events(title,event_date,location,description)
SELECT 'Alumni Networking Meetup','2026-10-15 17:00:00','University Main Hall','Connect with alumni and build professional relationships.'
WHERE NOT EXISTS (SELECT 1 FROM events WHERE title='Alumni Networking Meetup');

INSERT INTO events(title,event_date,location,description)
SELECT 'Career Development Session','2026-11-05 15:00:00','Seminar Hall','A session focused on careers, internships and professional growth.'
WHERE NOT EXISTS (SELECT 1 FROM events WHERE title='Career Development Session');

INSERT INTO jobs(title,company,location,description)
SELECT 'Junior Software Engineer','Tech Solutions','Lahore','Entry-level software engineering opportunity.'
WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE title='Junior Software Engineer');

INSERT INTO jobs(title,company,location,description)
SELECT 'Web Developer','Digital Labs','Karachi','Web development position working with modern web technologies.'
WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE title='Web Developer');

-- Add role to existing installations if it is missing.
SET @role_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'alumni' AND COLUMN_NAME = 'role');
SET @role_sql = IF(@role_exists = 0, "ALTER TABLE alumni ADD COLUMN role ENUM('alumni','admin') NOT NULL DEFAULT 'alumni'", 'SELECT 1');
PREPARE role_stmt FROM @role_sql;
EXECUTE role_stmt;
DEALLOCATE PREPARE role_stmt;

-- Promote an existing account after setup:
-- UPDATE alumni SET role='admin' WHERE email='your-admin-email@example.com';
