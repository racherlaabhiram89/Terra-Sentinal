"""APAAR-based Student Data Management & Verification Platform for AICTE-approved institutions."""
import csv
import io
import json
import os
import secrets
import time
from typing import List, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import analytics
from db import get_db, init_db
from security import (audit, audit_chain_ok, check_password, dec, decode_token, hash_key, make_token,
                      mask_apaar, mask_name, new_api_key, now, sign)
from seed import seed_if_empty
from validation import clean, recompute_status, upsert_student

app = FastAPI(title="AICTE APAAR Student Data Platform", version="1.0")
bearer = HTTPBearer(auto_error=False)
ADMIN, INST, EMP, REG = "aicte_admin", "institution", "employer", "regulator"


@app.on_event("startup")
def startup():
    init_db()
    seed_if_empty()


# ------------------------------------------------------------------ auth / RBAC
def current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
                 x_api_key: Optional[str] = Header(None), conn=Depends(get_db)):
    if x_api_key:  # machine-to-machine integration for institutional ERP systems
        inst = conn.execute("SELECT * FROM institutions WHERE api_key_hash=?", (hash_key(x_api_key),)).fetchone()
        if not inst:
            raise HTTPException(401, "Invalid API key")
        return {"username": f"api:{inst['code']}", "role": INST, "institution_id": inst["id"]}
    if not creds:
        raise HTTPException(401, "Authentication required")
    try:
        p = decode_token(creds.credentials)
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    return {"username": p["sub"], "role": p["role"], "institution_id": p["inst"]}


def roles(*allowed):
    def dep(user=Depends(current_user)):
        if user["role"] not in allowed:
            raise HTTPException(403, f"Role '{user['role']}' is not permitted to do this")
        return user
    return dep


def scope_inst(user, requested: Optional[int] = None):
    """Institutions are locked to their own data; admins/regulators may pick any."""
    if user["role"] == INST:
        return user["institution_id"]
    return requested


_fails = {}


class LoginReq(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(body: LoginReq, conn=Depends(get_db)):
    tries = [t for t in _fails.get(body.username, []) if time.time() - t < 300]
    if len(tries) >= 5:
        raise HTTPException(429, "Too many failed attempts. Try again in 5 minutes.")
    u = conn.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if not u or not check_password(body.password, u["pw_hash"]):
        _fails[body.username] = tries + [time.time()]
        audit(conn, body.username, "-", "LOGIN_FAILED")
        conn.commit()
        raise HTTPException(401, "Wrong username or password")
    _fails.pop(body.username, None)
    audit(conn, u["username"], u["role"], "LOGIN")
    inst = conn.execute("SELECT name FROM institutions WHERE id=?", (u["institution_id"],)).fetchone()
    return {"token": make_token(u), "role": u["role"], "name": u["full_name"],
            "institution_id": u["institution_id"], "institution": inst["name"] if inst else None}


# ------------------------------------------------------------------ institutions / courses
@app.get("/api/institutions")
def institutions(user=Depends(roles(ADMIN, REG)), conn=Depends(get_db)):
    return [dict(r) | {"api_key_hash": None} for r in conn.execute("SELECT id,code,name,state FROM institutions")]


@app.post("/api/institutions/{inst_id}/api-key")
def create_api_key(inst_id: int, user=Depends(roles(ADMIN)), conn=Depends(get_db)):
    key = new_api_key()
    conn.execute("UPDATE institutions SET api_key_hash=? WHERE id=?", (hash_key(key), inst_id))
    audit(conn, user["username"], user["role"], "API_KEY_ISSUED", str(inst_id))
    return {"api_key": key, "note": "Store this now - it cannot be shown again. Send as header X-API-Key."}


class CourseIn(BaseModel):
    institution_id: int
    name: str
    academic_year: str
    approved_intake: int
    supernumerary_cap: int = 0


@app.post("/api/courses")
def set_course(c: CourseIn, user=Depends(roles(ADMIN)), conn=Depends(get_db)):
    from validation import refresh_intake
    conn.execute("""INSERT INTO courses(institution_id,name,academic_year,approved_intake,supernumerary_cap)
                    VALUES(?,?,?,?,?) ON CONFLICT(institution_id,name,academic_year)
                    DO UPDATE SET approved_intake=excluded.approved_intake, supernumerary_cap=excluded.supernumerary_cap""",
                 (c.institution_id, c.name, c.academic_year, c.approved_intake, c.supernumerary_cap))
    refresh_intake(conn, c.institution_id, c.name, c.academic_year)
    audit(conn, user["username"], user["role"], "COURSE_INTAKE_SET", f"{c.institution_id}:{c.name}",
          f"{c.academic_year} intake={c.approved_intake} super={c.supernumerary_cap}")
    return {"ok": True}


@app.get("/api/courses")
def courses(institution_id: Optional[int] = None, user=Depends(roles(ADMIN, INST, REG)), conn=Depends(get_db)):
    iid = scope_inst(user, institution_id)
    q, a = ("SELECT c.*, i.name inst FROM courses c JOIN institutions i ON i.id=c.institution_id", ())
    if iid:
        q, a = q + " WHERE c.institution_id=?", (iid,)
    return [dict(r) for r in conn.execute(q + " ORDER BY i.name, c.name", a)]


# ------------------------------------------------------------------ student data upload
class StudentIn(BaseModel):
    apaar_id: str = ""
    student_id: str = ""
    name: str = ""
    dob: str = ""
    gender: str = ""
    course: str = ""
    academic_year: str = ""
    admission_date: str = ""
    category: str = "General"
    seat_type: str = "regular"
    nri: bool = False
    oci: bool = False
    foreign_national: bool = False
    nationality: str = "Indian"
    email: str = ""
    phone: str = ""


def _store_many(conn, user, inst_id, rows):
    results, seen = [], set()
    for n, raw in enumerate(rows, 1):
        s = clean(raw)
        key = (s["apaar_id"], s["academic_year"])
        if s["apaar_id"] and key in seen:
            results.append({"row": n, "apaar_id": s["apaar_id"], "status": "skipped",
                            "issues": [{"code": "DUPLICATE_IN_FILE", "severity": "error",
                                        "message": "Duplicate APAAR ID inside the same upload; later row ignored"}]})
            continue
        seen.add(key)
        sid, status, issues, created = upsert_student(conn, inst_id, raw)
        results.append({"row": n, "id": sid, "apaar_id": s["apaar_id"], "status": status,
                        "created": created, "issues": issues})
    summary = {}
    for r in results:
        summary[r["status"]] = summary.get(r["status"], 0) + 1
    audit(conn, user["username"], user["role"], "STUDENT_UPLOAD", f"inst:{inst_id}",
          json.dumps({"rows": len(rows), **summary}))
    return {"count": len(rows), "summary": summary, "results": results}


def _inst_for_upload(user, institution_id):
    iid = scope_inst(user, institution_id)
    if not iid:
        raise HTTPException(400, "institution_id is required for admin uploads")
    return iid


@app.post("/api/students")
def add_student(s: StudentIn, institution_id: Optional[int] = None, user=Depends(roles(INST, ADMIN)),
                conn=Depends(get_db)):
    return _store_many(conn, user, _inst_for_upload(user, institution_id), [s.model_dump()])


@app.post("/api/students/bulk")
def add_bulk(rows: List[StudentIn], institution_id: Optional[int] = None, user=Depends(roles(INST, ADMIN)),
             conn=Depends(get_db)):
    return _store_many(conn, user, _inst_for_upload(user, institution_id), [r.model_dump() for r in rows])


@app.post("/api/students/upload-csv")
async def upload_csv(file: UploadFile = File(...), institution_id: Optional[int] = None,
                     user=Depends(roles(INST, ADMIN)), conn=Depends(get_db)):
    text = (await file.read()).decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise HTTPException(400, "CSV has no data rows")
    if len(rows) > 20000:
        raise HTTPException(400, "Maximum 20,000 rows per upload")
    return _store_many(conn, user, _inst_for_upload(user, institution_id), rows)


CSV_HEADER = ("apaar_id,student_id,name,dob,gender,course,academic_year,admission_date,category,seat_type,"
              "nri,oci,foreign_national,nationality,email,phone\n")


@app.get("/api/students/template.csv")
def template():
    return Response(CSV_HEADER, media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=student_upload_template.csv"})


@app.get("/api/students")
def list_students(q: str = "", status: str = "", course: str = "", institution_id: Optional[int] = None,
                  limit: int = Query(50, le=500), offset: int = 0,
                  user=Depends(roles(ADMIN, INST, REG)), conn=Depends(get_db)):
    iid = scope_inst(user, institution_id)
    where, args = ["1=1"], []
    if iid:
        where.append("s.institution_id=?"); args.append(iid)
    if status:
        where.append("s.status=?"); args.append(status)
    if course:
        where.append("s.course=?"); args.append(course)
    if q:
        where.append("(s.name LIKE ? OR s.apaar_id LIKE ? OR s.student_id LIKE ?)"); args += [f"%{q}%"] * 3
    w = " AND ".join(where)
    total = conn.execute(f"SELECT COUNT(*) c FROM students s WHERE {w}", args).fetchone()["c"]
    rows = conn.execute(
        f"""SELECT s.id,s.apaar_id,s.student_id,s.name,s.course,s.academic_year,s.seat_type,s.nri,s.oci,
            s.foreign_national,s.status,i.name inst,
            (SELECT COUNT(*) FROM issues x WHERE x.student_id=s.id AND x.resolved=0) open_issues
            FROM students s JOIN institutions i ON i.id=s.institution_id WHERE {w}
            ORDER BY s.id DESC LIMIT ? OFFSET ?""", args + [limit, offset]).fetchall()
    return {"total": total, "items": [dict(r) for r in rows]}


@app.get("/api/students/{sid}")
def student_detail(sid: int, user=Depends(roles(ADMIN, INST, REG)), conn=Depends(get_db)):
    s = conn.execute("SELECT s.*, i.name inst FROM students s JOIN institutions i ON i.id=s.institution_id WHERE s.id=?",
                     (sid,)).fetchone()
    if not s or (user["role"] == INST and s["institution_id"] != user["institution_id"]):
        raise HTTPException(404, "Student not found")
    d = dict(s)
    email, phone = dec(d.pop("email_enc")), dec(d.pop("phone_enc"))
    if user["role"] == INST:
        d["email"], d["phone"] = email, phone
    audit(conn, user["username"], user["role"], "STUDENT_VIEW", str(sid))
    d["issues"] = [dict(r) for r in conn.execute("SELECT * FROM issues WHERE student_id=?", (sid,))]
    return d


# ------------------------------------------------------------------ issues
@app.get("/api/issues")
def issues(include_resolved: bool = False, institution_id: Optional[int] = None,
           user=Depends(roles(ADMIN, INST, REG)), conn=Depends(get_db)):
    iid = scope_inst(user, institution_id)
    w, a = ["1=1"], []
    if not include_resolved:
        w.append("x.resolved=0")
    if iid:
        w.append("x.institution_id=?"); a.append(iid)
    rows = conn.execute(f"""SELECT x.*, s.name, s.apaar_id, i.name inst FROM issues x
                            JOIN students s ON s.id=x.student_id JOIN institutions i ON i.id=x.institution_id
                            WHERE {' AND '.join(w)} ORDER BY CASE x.severity WHEN 'error' THEN 0 ELSE 1 END, x.id DESC
                            LIMIT 500""", a).fetchall()
    return [dict(r) for r in rows]


class ResolveReq(BaseModel):
    note: str


@app.post("/api/issues/{issue_id}/resolve")
def resolve(issue_id: int, body: ResolveReq, user=Depends(roles(ADMIN, INST)), conn=Depends(get_db)):
    x = conn.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
    if not x or (user["role"] == INST and x["institution_id"] != user["institution_id"]):
        raise HTTPException(404, "Issue not found")
    if len(body.note.strip()) < 5:
        raise HTTPException(400, "A resolution note of at least 5 characters is required")
    conn.execute("UPDATE issues SET resolved=1, resolution_note=? WHERE id=?", (body.note, issue_id))
    recompute_status(conn, x["student_id"])
    audit(conn, user["username"], user["role"], "ISSUE_RESOLVED", str(issue_id), body.note)
    return {"ok": True}


# ------------------------------------------------------------------ dashboards / anomalies
@app.get("/api/dashboard")
def dashboard(institution_id: Optional[int] = None, user=Depends(roles(ADMIN, INST, REG)), conn=Depends(get_db)):
    return analytics.dashboard(conn, scope_inst(user, institution_id))


@app.get("/api/anomalies")
def anomalies(user=Depends(roles(ADMIN, REG)), conn=Depends(get_db)):
    return analytics.anomalies(conn)


@app.get("/api/apaar/lookup/{apaar_id}")
def apaar_lookup(apaar_id: str, user=Depends(roles(ADMIN, INST)), conn=Depends(get_db)):
    """Adapter for the national APAAR registry (mocked locally; replace body with the real API call)."""
    r = conn.execute("SELECT * FROM apaar_registry WHERE apaar_id=?", (apaar_id,)).fetchone()
    return {"valid": bool(r), "name_masked": mask_name(r["name"]) if r else None}


# ------------------------------------------------------------------ consent
class ConsentReq(BaseModel):
    apaar_id: str
    dob: str
    granted: bool
    scope: str = "employment-verification"


@app.post("/api/consent")
def consent(c: ConsentReq, conn=Depends(get_db)):
    """Student-facing. Production: authenticate via DigiLocker/OTP. Demo: APAAR ID + DOB."""
    r = conn.execute("SELECT dob FROM apaar_registry WHERE apaar_id=?", (c.apaar_id,)).fetchone()
    if not r or r["dob"] != c.dob:
        raise HTTPException(403, "APAAR ID and date of birth do not match")
    conn.execute("INSERT INTO consents(apaar_id,granted,scope,ts) VALUES(?,?,?,?)",
                 (c.apaar_id, int(c.granted), c.scope, now()))
    audit(conn, f"student:{mask_apaar(c.apaar_id)}", "student", "CONSENT_GRANTED" if c.granted else "CONSENT_REVOKED", c.scope)
    return {"ok": True, "granted": c.granted}


def has_consent(conn, apaar_id):
    r = conn.execute("SELECT granted FROM consents WHERE apaar_id=? ORDER BY id DESC LIMIT 1", (apaar_id,)).fetchone()
    return bool(r and r["granted"])


# ------------------------------------------------------------------ verification
class VerifyReq(BaseModel):
    apaar_id: str
    purpose: str = "employment verification"


@app.post("/api/verify")
def verify(v: VerifyReq, user=Depends(roles(EMP, REG, ADMIN)), conn=Depends(get_db)):
    a = v.apaar_id.replace(" ", "").replace("-", "")
    rows = conn.execute("""SELECT s.*, i.name inst FROM students s JOIN institutions i ON i.id=s.institution_id
                           WHERE s.apaar_id=?""", (a,)).fetchall()
    consent_ok = user["role"] in (REG, ADMIN) or has_consent(conn, a)
    audit(conn, user["username"], user["role"], "VERIFY_REQUEST", mask_apaar(a),
          f"purpose={v.purpose}; consent={'ok' if consent_ok else 'missing'}; found={len(rows)}")
    if not consent_ok and rows:
        conn.commit()
        raise HTTPException(403, "The student has not given consent for this verification. "
                                 "Ask them to grant consent on the Consent page.")
    if not rows:
        return {"found": False, "verified": False, "records": []}
    recs = [{"institution": r["inst"], "course": r["course"], "academic_year": r["academic_year"],
             "student_id": r["student_id"], "enrolment": r["enrol_status"], "record_status": r["status"],
             "name": r["name"] if consent_ok else mask_name(r["name"])} for r in rows]
    return {"found": True, "apaar_id": mask_apaar(a),
            "verified": any(r["record_status"] in ("verified", "warning") for r in recs), "records": recs}


def _issue_record(conn, s, actor):
    payload = {"apaar_id": s["apaar_id"], "student_id": s["student_id"], "name": s["name"],
               "institution": s["inst"], "course": s["course"], "academic_year": s["academic_year"],
               "issued_at": now()}
    token = secrets.token_urlsafe(12)
    sig = sign(payload)
    conn.execute("INSERT INTO records(token,apaar_id,payload,signature,issued_by,issued_at) VALUES(?,?,?,?,?,?)",
                 (token, s["apaar_id"], json.dumps(payload), sig, actor, payload["issued_at"]))
    return token, payload, sig


def _own_student(conn, user, sid):
    s = conn.execute("SELECT s.*, i.name inst FROM students s JOIN institutions i ON i.id=s.institution_id WHERE s.id=?",
                     (sid,)).fetchone()
    if not s or (user["role"] == INST and s["institution_id"] != user["institution_id"]):
        raise HTTPException(404, "Student not found")
    if s["status"] in ("rejected",):
        raise HTTPException(409, "Record is rejected - fix the data before issuing a verifiable record")
    return s


@app.post("/api/records/issue/{sid}")
def issue_record(sid: int, user=Depends(roles(INST, ADMIN)), conn=Depends(get_db)):
    s = _own_student(conn, user, sid)
    token, payload, sig = _issue_record(conn, s, user["username"])
    audit(conn, user["username"], user["role"], "RECORD_ISSUED", token, mask_apaar(s["apaar_id"]))
    return {"token": token, "signature": sig, "payload": payload, "verify_path": f"/api/records/check/{token}"}


@app.get("/api/records/check/{token}")
def check_record(token: str, conn=Depends(get_db)):
    """Public: anyone holding the token (e.g. via QR on a certificate) can check authenticity."""
    r = conn.execute("SELECT * FROM records WHERE token=?", (token,)).fetchone()
    if not r:
        return {"valid": False, "reason": "Unknown token"}
    payload = json.loads(r["payload"])
    ok = sign(payload) == r["signature"]
    live = conn.execute("SELECT status FROM students WHERE apaar_id=? AND academic_year=? AND student_id=?",
                        (payload["apaar_id"], payload["academic_year"], payload["student_id"])).fetchone()
    return {"valid": ok and bool(live), "signature_ok": ok, "live_status": live["status"] if live else "missing",
            "record": {"apaar_id": mask_apaar(payload["apaar_id"]), "student_id": payload["student_id"],
                       "name": mask_name(payload["name"]), "institution": payload["institution"],
                       "course": payload["course"], "academic_year": payload["academic_year"],
                       "issued_at": payload["issued_at"]}}


@app.get("/api/certificate/{sid}")
def certificate(sid: int, user=Depends(roles(INST, ADMIN)), conn=Depends(get_db)):
    """Line to print on degree certificates: APAAR ID beside student ID, with verification token."""
    s = _own_student(conn, user, sid)
    token, _, _ = _issue_record(conn, s, user["username"])
    a = s["apaar_id"]
    spaced = f"{a[:4]} {a[4:8]} {a[8:]}"
    audit(conn, user["username"], user["role"], "CERT_LINE_GENERATED", token)
    return {"line": f"APAAR ID: {spaced}  |  Student ID: {s['student_id']}",
            "verify_token": token, "verify_url": f"/api/records/check/{token}",
            "html": f"<p class='cert-ids'>APAAR ID: <b>{spaced}</b> &nbsp;|&nbsp; Student ID: <b>{s['student_id']}</b></p>"}


# ------------------------------------------------------------------ audit & reports
@app.get("/api/audit")
def audit_log(limit: int = Query(100, le=1000), user=Depends(roles(ADMIN, REG)), conn=Depends(get_db)):
    ok, bad = audit_chain_ok(conn)
    rows = conn.execute("SELECT id,ts,actor,role,action,target,detail FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    return {"chain_intact": ok, "first_broken_id": bad, "entries": [dict(r) for r in rows]}


def _report(conn, kind):
    if kind == "institution-summary":
        return analytics.utilisation(conn)
    if kind == "excess-enrolment":
        return [u for u in analytics.utilisation(conn) if u["utilisation_pct"] and u["utilisation_pct"] > 100]
    if kind == "state-wise":
        return [dict(r) for r in conn.execute(
            """SELECT i.state, COUNT(*) students, SUM(s.nri) nri, SUM(s.oci) oci, SUM(s.foreign_national) foreign_nationals,
               SUM(s.status IN ('flagged','rejected')) flagged FROM students s JOIN institutions i ON i.id=s.institution_id
               GROUP BY i.state ORDER BY students DESC""")]
    if kind == "course-wise":
        return [dict(r) for r in conn.execute(
            "SELECT course, academic_year, COUNT(*) students FROM students GROUP BY course, academic_year ORDER BY students DESC")]
    if kind == "open-issues":
        return [dict(r) for r in conn.execute(
            """SELECT i.name institution, x.code, x.severity, x.message, s.apaar_id, s.student_id
               FROM issues x JOIN students s ON s.id=x.student_id JOIN institutions i ON i.id=x.institution_id
               WHERE x.resolved=0 ORDER BY i.name""")]
    if kind == "anomalies":
        return analytics.anomalies(conn)
    raise HTTPException(404, "Unknown report")


@app.get("/api/reports/{kind}")
def report(kind: str, format: str = "json", user=Depends(roles(ADMIN, REG)), conn=Depends(get_db)):
    data = _report(conn, kind)
    audit(conn, user["username"], user["role"], "REPORT", kind, format)
    if format == "csv":
        buf = io.StringIO()
        if data:
            w = csv.DictWriter(buf, fieldnames=list(data[0].keys()))
            w.writeheader(); w.writerows(data)
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={kind}.csv"})
    return data


app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True), name="static")
