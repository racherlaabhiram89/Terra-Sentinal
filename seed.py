"""Demo data: institutions, users, a mock APAAR registry and students with deliberate problems."""
import random

from db import connect, init_db
from security import hash_password
from validation import upsert_student

YEAR = "2026-27"
FIRST = ["Aarav", "Vihaan", "Ananya", "Diya", "Rohan", "Sneha", "Karthik", "Priya", "Arjun", "Meera", "Ishaan",
         "Kavya", "Rahul", "Nandini", "Sai", "Lakshmi", "Varun", "Pooja", "Aditya", "Harini"]
LAST = ["Reddy", "Sharma", "Rao", "Patel", "Iyer", "Naidu", "Gupta", "Kumar", "Singh", "Das"]

INSTS = [("TS001", "Ace Engineering College", "Telangana"),
         ("TS002", "Deccan Institute of Technology", "Telangana"),
         ("KA001", "Bengaluru Institute of Technology", "Karnataka"),
         ("MH001", "Sahyadri College of Engineering", "Maharashtra")]
COURSES = [("B.Tech CSE", 8, 2), ("B.Tech ECE", 6, 1), ("MBA", 5, 0)]


def seed_if_empty():
    init_db()
    c = connect()
    if c.execute("SELECT COUNT(*) n FROM institutions").fetchone()["n"]:
        c.close()
        return
    random.seed(7)
    # --- institutions, intake, users
    for code, name, state in INSTS:
        cur = c.execute("INSERT INTO institutions(code,name,state) VALUES(?,?,?)", (code, name, state))
        iid = cur.lastrowid
        for course, intake, sup in COURSES:
            c.execute("INSERT INTO courses(institution_id,name,academic_year,approved_intake,supernumerary_cap) VALUES(?,?,?,?,?)",
                      (iid, course, YEAR, intake, sup))
        c.execute("INSERT INTO users(username,pw_hash,role,institution_id,full_name) VALUES(?,?,?,?,?)",
                  (f"inst{iid}", hash_password("inst123"), "institution", iid, f"{name} Admissions Office"))
    for u, pw, role, nm in [("admin", "admin123", "aicte_admin", "AICTE Regulation Bureau"),
                            ("employer", "emp123", "employer", "Demo Employer HR"),
                            ("regulator", "reg123", "regulator", "NBA / UGC Auditor")]:
        c.execute("INSERT INTO users(username,pw_hash,role,institution_id,full_name) VALUES(?,?,?,?,?)",
                  (u, hash_password(pw), role, None, nm))

    # --- mock national registry of 120 people
    people = []
    for i in range(120):
        apaar = str(100000000000 + random.randint(0, 899999999999))
        name = f"{random.choice(FIRST)} {random.choice(LAST)}"
        dob = f"200{random.randint(3, 8)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
        people.append({"apaar_id": apaar, "name": name, "dob": dob, "gender": random.choice(["M", "F"])})
        c.execute("INSERT OR IGNORE INTO apaar_registry VALUES(?,?,?,?)", (apaar, name, dob, people[-1]["gender"]))
    c.commit()

    def rec(p, sid, course, **kw):
        d = dict(apaar_id=p["apaar_id"], student_id=sid, name=p["name"], dob=p["dob"], gender=p["gender"],
                 course=course, academic_year=YEAR, admission_date="2026-08-10", category="General",
                 seat_type="regular", nationality="Indian", email=f"{sid.lower()}@example.edu", phone="9000000000")
        d.update(kw)
        return d

    # --- clean admissions for institutions 1-3
    k = 0
    for iid in (1, 2, 3):
        for course, intake, _ in COURSES:
            for n in range(intake if iid == 3 else intake - (3 if iid == 1 else 1)):
                p = people[k % 100]; k += 1
                upsert_student(c, iid, rec(p, f"I{iid}-{course[:3]}-{n + 1:03d}", course))

    # --- deliberate problems (shown in demo) ---
    p = people[110]
    upsert_student(c, 1, rec(p, "I1-X-001", "MBA", apaar_id="12345"))                           # invalid APAAR
    upsert_student(c, 1, rec(people[111], "I1-X-002", "MBA", apaar_id="999999999999"))          # not in registry
    upsert_student(c, 1, rec(people[112], "I1-X-003", "MBA", name="Totally Different Person"))  # name mismatch
    upsert_student(c, 1, rec(people[113], "I1-X-004", "B.Tech ECE", foreign_national=True, nri=True,
                             nationality="Indian"))                                              # inconsistent
    # excess enrolment at institution 4 (MBA intake 5, enrol 8)
    for n in range(8):
        upsert_student(c, 4, rec(people[60 + n], f"I4-MBA-{n + 1:03d}", "MBA"))
    # cross-institution duplicate: same person at institution 2 and 4
    dup = people[105]
    upsert_student(c, 2, rec(dup, "I2-DUP-001", "B.Tech CSE", seat_type="supernumerary", oci=True))
    upsert_student(c, 4, rec(dup, "I4-DUP-001", "B.Tech CSE"))
    # placeholder DOB cluster at institution 4
    for n in range(6):
        q = people[80 + n]
        upsert_student(c, 4, rec(q, f"I4-ECE-{n + 1:03d}", "B.Tech ECE", dob="2005-01-01"))
    c.commit()
    c.close()
    print("Seeded demo data. Logins: admin/admin123, inst1/inst123 (inst1..inst4), employer/emp123, regulator/reg123")


if __name__ == "__main__":
    seed_if_empty()
