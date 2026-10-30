"""SQLite storage layer. Swap for PostgreSQL in production (same SQL, change the driver)."""
import os
import sqlite3

DB_PATH = os.environ.get("APAAR_DB", os.path.join(os.path.dirname(__file__), "apaar.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS institutions(
  id INTEGER PRIMARY KEY, code TEXT UNIQUE, name TEXT, state TEXT, api_key_hash TEXT
);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT, role TEXT,
  institution_id INTEGER REFERENCES institutions(id), full_name TEXT
);
CREATE TABLE IF NOT EXISTS courses(
  id INTEGER PRIMARY KEY, institution_id INTEGER REFERENCES institutions(id),
  name TEXT, academic_year TEXT, approved_intake INTEGER, supernumerary_cap INTEGER DEFAULT 0,
  UNIQUE(institution_id, name, academic_year)
);
-- Mock of the national APAAR / Academic Bank of Credits registry (replace with real API adapter)
CREATE TABLE IF NOT EXISTS apaar_registry(
  apaar_id TEXT PRIMARY KEY, name TEXT, dob TEXT, gender TEXT
);
CREATE TABLE IF NOT EXISTS students(
  id INTEGER PRIMARY KEY, apaar_id TEXT, institution_id INTEGER REFERENCES institutions(id),
  student_id TEXT, name TEXT, dob TEXT, gender TEXT, course TEXT, academic_year TEXT,
  admission_date TEXT, category TEXT, seat_type TEXT DEFAULT 'regular',
  nri INTEGER DEFAULT 0, oci INTEGER DEFAULT 0, foreign_national INTEGER DEFAULT 0,
  nationality TEXT DEFAULT 'Indian', email_enc TEXT, phone_enc TEXT,
  enrol_status TEXT DEFAULT 'active', status TEXT DEFAULT 'verified',
  created_at TEXT, updated_at TEXT,
  UNIQUE(apaar_id, institution_id, academic_year)
);
CREATE INDEX IF NOT EXISTS idx_students_apaar ON students(apaar_id);
CREATE INDEX IF NOT EXISTS idx_students_group ON students(institution_id, course, academic_year);
CREATE TABLE IF NOT EXISTS issues(
  id INTEGER PRIMARY KEY, student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
  institution_id INTEGER, code TEXT, severity TEXT, message TEXT,
  resolved INTEGER DEFAULT 0, resolution_note TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS consents(
  id INTEGER PRIMARY KEY, apaar_id TEXT, granted INTEGER, scope TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, role TEXT, action TEXT, target TEXT,
  detail TEXT, prev_hash TEXT, hash TEXT
);
CREATE TABLE IF NOT EXISTS records(
  token TEXT PRIMARY KEY, apaar_id TEXT, payload TEXT, signature TEXT, issued_by TEXT, issued_at TEXT
);
"""


def connect():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init_db():
    c = connect()
    c.executescript(SCHEMA)
    c.commit()
    c.close()


def get_db():
    """FastAPI dependency: one connection per request, committed on success."""
    c = connect()
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()
