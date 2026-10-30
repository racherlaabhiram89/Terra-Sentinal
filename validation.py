"""Automated validation: APAAR checks, duplicates, intake limits, inconsistencies, cross-institution enrolment."""
import datetime as dt
import difflib
import re

from security import enc, now

REQUIRED = ["apaar_id", "student_id", "name", "dob", "course", "academic_year"]
INTAKE_CODES = ("INTAKE_EXCEEDED", "SUPERNUMERARY_EXCEEDED", "COURSE_NOT_APPROVED")
REJECT_CODES = {"APAAR_INVALID", "APAAR_NOT_FOUND", "MISSING_FIELD"}


def tb(v):
    return str(v).strip().lower() in ("1", "true", "yes", "y", "t")


def norm(s):
    return re.sub(r"[^a-z ]", "", (s or "").lower()).strip()


def clean(s):
    """Normalise a raw student dict (from JSON or CSV)."""
    d = {k: (str(v).strip() if isinstance(v, str) else v) for k, v in s.items()}
    d["apaar_id"] = re.sub(r"[\s-]", "", str(d.get("apaar_id") or ""))
    for k in ("nri", "oci", "foreign_national"):
        d[k] = 1 if tb(d.get(k, 0)) else 0
    d["seat_type"] = (d.get("seat_type") or "regular").lower()
    d["nationality"] = d.get("nationality") or "Indian"
    for k in ("student_id", "name", "dob", "gender", "course", "academic_year", "category",
              "admission_date", "email", "phone"):
        d[k] = str(d.get(k) or "").strip()
    return d


def row_issues(conn, inst_id, s, row_id=None):
    """Return [(code, severity, message)] for one student record."""
    out = []
    add = lambda c, sev, m: out.append((c, sev, m))

    for f in REQUIRED:
        if not s.get(f):
            add("MISSING_FIELD", "error", f"Required field '{f}' is missing")

    a = s.get("apaar_id")
    if a:
        if not re.fullmatch(r"\d{12}", a):
            add("APAAR_INVALID", "error", "APAAR ID must be exactly 12 digits")
        else:
            reg = conn.execute("SELECT * FROM apaar_registry WHERE apaar_id=?", (a,)).fetchone()
            if not reg:
                add("APAAR_NOT_FOUND", "error", "APAAR ID not found in the national registry")
            else:
                ratio = difflib.SequenceMatcher(None, norm(reg["name"]), norm(s["name"])).ratio()
                if ratio < 0.75:
                    add("APAAR_NAME_MISMATCH", "error",
                        f"Name does not match registry record ({ratio:.0%} similar)")
                if reg["dob"] != s["dob"]:
                    add("APAAR_DOB_MISMATCH", "error", "Date of birth differs from the registry record")
            for r in conn.execute(
                """SELECT i.name FROM students st JOIN institutions i ON i.id=st.institution_id
                   WHERE st.apaar_id=? AND st.institution_id!=? AND st.academic_year=?
                   AND st.enrol_status='active'""", (a, inst_id, s["academic_year"])):
                add("CROSS_INSTITUTION_DUPLICATE", "error",
                    f"Same APAAR ID is also enrolled at {r['name']} for {s['academic_year']}")

    if s.get("student_id"):
        r = conn.execute(
            "SELECT apaar_id FROM students WHERE institution_id=? AND student_id=? AND apaar_id!=? AND id IS NOT ?",
            (inst_id, s["student_id"], a, row_id)).fetchone()
        if r:
            add("DUPLICATE_STUDENT_ID", "error",
                f"Student ID {s['student_id']} is already used for another APAAR ID at this institution")

    # --- consistency rules ---
    nat = norm(s["nationality"])
    fn, nri, oci = s["foreign_national"], s["nri"], s["oci"]
    if fn and nri:
        add("INCONSISTENT_DATA", "error", "A student cannot be both NRI and Foreign National")
    if fn and oci:
        add("INCONSISTENT_DATA", "error", "OCI and Foreign National are mutually exclusive categories")
    if nri and oci:
        add("INCONSISTENT_DATA", "error", "A student cannot be both NRI and OCI")
    if nat == "indian" and fn:
        add("INCONSISTENT_DATA", "error", "Nationality is Indian but Foreign National flag is set")
    if nat != "indian" and not (fn or oci or nri):
        add("INCONSISTENT_DATA", "warning", f"Nationality is {s['nationality']} but no FN/OCI/NRI flag is set")
    if s["seat_type"] == "supernumerary" and not (fn or oci or nri):
        add("INCONSISTENT_DATA", "warning", "Supernumerary seat used without FN/OCI/NRI category")
    if s["seat_type"] not in ("regular", "supernumerary"):
        add("INCONSISTENT_DATA", "error", "seat_type must be 'regular' or 'supernumerary'")

    try:
        dob = dt.date.fromisoformat(s["dob"]) if s["dob"] else None
        if dob:
            age = (dt.date.today() - dob).days / 365.25
            if dob >= dt.date.today():
                add("INCONSISTENT_DATA", "error", "Date of birth is in the future")
            elif age < 15 or age > 45:
                add("INCONSISTENT_DATA", "warning", f"Unusual age for enrolment ({age:.0f} years)")
            if s.get("admission_date"):
                adm = dt.date.fromisoformat(s["admission_date"])
                if adm <= dob:
                    add("INCONSISTENT_DATA", "error", "Admission date is before date of birth")
    except ValueError:
        add("INCONSISTENT_DATA", "error", "Dates must be in YYYY-MM-DD format")
    return out


def recompute_status(conn, student_id):
    rows = conn.execute("SELECT code, severity FROM issues WHERE student_id=? AND resolved=0",
                        (student_id,)).fetchall()
    if any(r["code"] in REJECT_CODES for r in rows):
        st = "rejected"
    elif any(r["severity"] == "error" for r in rows):
        st = "flagged"
    elif rows:
        st = "warning"
    else:
        st = "verified"
    conn.execute("UPDATE students SET status=? WHERE id=?", (st, student_id))


def _add_issue(conn, student_id, inst_id, code, sev, msg):
    conn.execute("INSERT INTO issues(student_id,institution_id,code,severity,message,created_at) VALUES(?,?,?,?,?,?)",
                 (student_id, inst_id, code, sev, msg, now()))


def refresh_intake(conn, inst_id, course, year):
    """Re-evaluate approved-intake / supernumerary limits for one course-year group."""
    ids = [r["id"] for r in conn.execute(
        "SELECT id FROM students WHERE institution_id=? AND course=? AND academic_year=?", (inst_id, course, year))]
    if ids:
        q = ",".join("?" * len(ids))
        conn.execute(f"DELETE FROM issues WHERE student_id IN ({q}) AND code IN ('INTAKE_EXCEEDED','SUPERNUMERARY_EXCEEDED','COURSE_NOT_APPROVED')", ids)
    c = conn.execute("SELECT * FROM courses WHERE institution_id=? AND name=? AND academic_year=?",
                     (inst_id, course, year)).fetchone()
    if not c:
        for i in ids:
            _add_issue(conn, i, inst_id, "COURSE_NOT_APPROVED", "error",
                       f"{course} ({year}) has no approved intake on record")
    else:
        for seat, cap, code in (("regular", c["approved_intake"], "INTAKE_EXCEEDED"),
                                ("supernumerary", c["supernumerary_cap"], "SUPERNUMERARY_EXCEEDED")):
            rows = conn.execute(
                "SELECT id FROM students WHERE institution_id=? AND course=? AND academic_year=? AND seat_type=? "
                "AND enrol_status='active' ORDER BY id", (inst_id, course, year, seat)).fetchall()
            for n, r in enumerate(rows):
                if n >= cap:
                    _add_issue(conn, r["id"], inst_id, code, "error",
                               f"Admission #{n + 1} exceeds approved {seat} seats ({cap})")
    for i in ids:
        recompute_status(conn, i)


def upsert_student(conn, inst_id, raw):
    """Insert/update a student, run all validations, return (row_id, status, issues, created)."""
    s = clean(raw)
    row = conn.execute("SELECT id FROM students WHERE apaar_id=? AND institution_id=? AND academic_year=?",
                       (s["apaar_id"], inst_id, s["academic_year"])).fetchone()
    vals = (s["student_id"], s["name"], s["dob"], s["gender"], s["course"], s["admission_date"], s["category"],
            s["seat_type"], s["nri"], s["oci"], s["foreign_national"], s["nationality"],
            enc(s["email"]), enc(s["phone"]), now())
    if row:
        sid, created = row["id"], False
        conn.execute("""UPDATE students SET student_id=?,name=?,dob=?,gender=?,course=?,admission_date=?,category=?,
                        seat_type=?,nri=?,oci=?,foreign_national=?,nationality=?,email_enc=?,phone_enc=?,updated_at=?
                        WHERE id=?""", vals + (sid,))
    else:
        cur = conn.execute("""INSERT INTO students(student_id,name,dob,gender,course,admission_date,category,seat_type,
                              nri,oci,foreign_national,nationality,email_enc,phone_enc,updated_at,
                              apaar_id,institution_id,academic_year,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                           vals + (s["apaar_id"], inst_id, s["academic_year"], now()))
        sid, created = cur.lastrowid, True

    placeholders = ",".join("?" * len(INTAKE_CODES))
    conn.execute(f"DELETE FROM issues WHERE student_id=? AND code NOT IN ({placeholders})", (sid,) + INTAKE_CODES)
    issues = row_issues(conn, inst_id, s, sid)
    for code, sev, msg in issues:
        _add_issue(conn, sid, inst_id, code, sev, msg)

    # flag the *other* side of a cross-institution duplicate too
    me = conn.execute("SELECT name FROM institutions WHERE id=?", (inst_id,)).fetchone()["name"]
    for o in conn.execute(
            "SELECT id, institution_id FROM students WHERE apaar_id=? AND institution_id!=? AND academic_year=? AND enrol_status='active'",
            (s["apaar_id"], inst_id, s["academic_year"])).fetchall():
        if not conn.execute("SELECT 1 FROM issues WHERE student_id=? AND code='CROSS_INSTITUTION_DUPLICATE' AND resolved=0",
                            (o["id"],)).fetchone():
            _add_issue(conn, o["id"], o["institution_id"], "CROSS_INSTITUTION_DUPLICATE", "error",
                       f"Same APAAR ID is also enrolled at {me} for {s['academic_year']}")
            recompute_status(conn, o["id"])

    refresh_intake(conn, inst_id, s["course"], s["academic_year"])
    recompute_status(conn, sid)
    status = conn.execute("SELECT status FROM students WHERE id=?", (sid,)).fetchone()["status"]
    all_issues = [dict(r) for r in conn.execute(
        "SELECT code,severity,message FROM issues WHERE student_id=? AND resolved=0", (sid,))]
    return sid, status, all_issues, created
