-- Codedemia Database Schema for Cloudflare D1
-- Drop existing tables for clean setup
DROP TABLE IF EXISTS bookings;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student', 'professor')),
    profile_picture TEXT,
    age INTEGER,
    gender TEXT,
    experience TEXT,
    goal TEXT,
    bio TEXT,
    github TEXT,
    linkedin TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Bookings table
CREATE TABLE bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    tutor_id INTEGER NOT NULL,
    language TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    duration REAL NOT NULL,
    meeting_type TEXT CHECK (meeting_type IN ('online', 'in-person', 'hybrid')),
    location TEXT,
    platform TEXT,
    notes TEXT,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected', 'completed', 'cancelled')),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (tutor_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sessions table (for authentication tokens)
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_bookings_student ON bookings(student_id);
CREATE INDEX idx_bookings_tutor ON bookings(tutor_id);
CREATE INDEX idx_bookings_status ON bookings(status);
CREATE INDEX idx_bookings_date ON bookings(date);
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- Insert test professor accounts
-- Password for all accounts: password123
-- Hash: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f (SHA-256)

INSERT INTO users (name, email, password, role, experience, bio) VALUES
('Sarah Johnson', 'sarah@codedemia.com', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'professor', 'advanced', 'HTML/CSS expert specializing in semantic markup and modern web standards. 5+ years teaching experience.'),
('Alex Thompson', 'alex@codedemia.com', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'professor', 'advanced', 'Full-stack JavaScript expert with extensive React and Node.js experience. Passionate about teaching modern web development.'),
('Robert Singh', 'robert@codedemia.com', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'professor', 'advanced', 'Senior Java architect specializing in enterprise applications and microservices. 10+ years industry experience.'),
('Emily Rodriguez', 'emily@codedemia.com', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'professor', 'advanced', 'Python expert with focus on web development and data science. Former Google engineer, now full-time educator.'),
('Andrew Miller', 'andrew@codedemia.com', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'professor', 'advanced', 'Systems programming expert with deep C++ knowledge. Specializes in algorithms, data structures, and performance optimization.');

-- Insert a test student account
INSERT INTO users (name, email, password, role, experience, goal) VALUES
('John Student', 'student@codedemia.com', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'student', 'beginner', 'Learn web development to build my own startup');

-- Insert sample bookings for testing
INSERT INTO bookings (student_id, tutor_id, language, date, time, duration, meeting_type, platform, notes, status) VALUES
(6, 1, 'HTML', '2025-01-20', '14:00', 2.0, 'online', 'Zoom', 'Need help with responsive design and CSS Grid', 'pending'),
(6, 2, 'JavaScript', '2025-01-22', '10:00', 1.5, 'online', 'Google Meet', 'Want to learn React basics', 'pending');