"""Anomaly detection (statistical + heuristic) and dashboard aggregates."""
import statistics
from collections import Counter, defaultdict

from validation import norm


def utilisation(conn, inst_id=None):
    """Per-institution intake vs. enrolment."""
    where, args = ("WHERE i.id=?", (inst_id,)) if inst_id else ("", ())
    rows = conn.execute(f"""
        SELECT i.id, i.name, i.state,
          COALESCE((SELECT SUM(approved_intake) FROM courses c WHERE c.institution_id=i.id),0) AS intake,
          (SELECT COUNT(*) FROM students s WHERE s.institution_id=i.id AND s.seat_type='regular'
             AND s.enrol_status='active') AS enrolled,
          (SELECT COUNT(*) FROM students s WHERE s.institution_id=i.id AND s.status IN ('flagged','rejected')) AS flagged
        FROM institutions i {where} ORDER BY i.name""", args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["utilisation_pct"] = round(100 * d["enrolled"] / d["intake"], 1) if d["intake"] else None
        out.append(d)
    return out


def dashboard(conn, inst_id=None):
    f, a = ("WHERE institution_id=?", (inst_id,)) if inst_id else ("", ())
    total = conn.execute(f"SELECT COUNT(*) c FROM students {f}", a).fetchone()["c"]
    by_status = {r["status"]: r["c"] for r in conn.execute(
        f"SELECT status, COUNT(*) c FROM students {f} GROUP BY status", a)}
    ia = (inst_id,) if inst_id else ()
    iw = "AND institution_id=?" if inst_id else ""
    top_issues = [dict(r) for r in conn.execute(
        f"SELECT code, severity, COUNT(*) c FROM issues WHERE resolved=0 {iw} GROUP BY code,severity ORDER BY c DESC LIMIT 8", ia)]
    by_course = [dict(r) for r in conn.execute(
        f"SELECT course, COUNT(*) c FROM students {f} GROUP BY course ORDER BY c DESC LIMIT 10", a)]
    cats = {"NRI": 0, "OCI": 0, "Foreign National": 0, "Supernumerary": 0}
    r = conn.execute(f"""SELECT SUM(nri) n, SUM(oci) o, SUM(foreign_national) f,
                         SUM(seat_type='supernumerary') s FROM students {f}""", a).fetchone()
    cats.update({"NRI": r["n"] or 0, "OCI": r["o"] or 0, "Foreign National": r["f"] or 0, "Supernumerary": r["s"] or 0})
    return {"total": total, "by_status": by_status, "top_issues": top_issues, "by_course": by_course,
            "categories": cats, "institutions": utilisation(conn, inst_id),
            "open_issues": conn.execute(f"SELECT COUNT(*) c FROM issues WHERE resolved=0 {iw}", ia).fetchone()["c"]}


def anomalies(conn):
    """Intelligent anomaly detection. Returns list of {type, severity, institution, detail}."""
    out = []
    util = utilisation(conn)

    # 1. Utilisation outliers (z-score across institutions) and hard overshoots
    ratios = [u["utilisation_pct"] for u in util if u["utilisation_pct"] is not None]
    mu = statistics.mean(ratios) if ratios else 0
    sd = statistics.pstdev(ratios) if len(ratios) > 2 else 0
    for u in util:
        p = u["utilisation_pct"]
        if p is None:
            continue
        if p > 100:
            out.append({"type": "EXCESS_ENROLMENT", "severity": "high", "institution": u["name"],
                        "detail": f"Enrolled {u['enrolled']} against approved intake {u['intake']} ({p}%)"})
        elif sd and (p - mu) / sd > 1.5:
            out.append({"type": "UTILISATION_OUTLIER", "severity": "medium", "institution": u["name"],
                        "detail": f"Utilisation {p}% is {(p - mu) / sd:.1f} std-devs above the national mean {mu:.0f}%"})

    # 2. DOB clustering (placeholder dates such as 01-01)
    by_inst = defaultdict(list)
    for r in conn.execute("""SELECT s.*, i.name inst FROM students s JOIN institutions i ON i.id=s.institution_id"""):
        by_inst[r["inst"]].append(r)
    for inst, rows in by_inst.items():
        n = len(rows)
        if n >= 10:
            dob, cnt = Counter(r["dob"] for r in rows).most_common(1)[0]
            if cnt >= max(5, 0.15 * n):
                out.append({"type": "DOB_CLUSTER", "severity": "medium", "institution": inst,
                            "detail": f"{cnt} of {n} students share DOB {dob} (possible placeholder data)"})
            # 3. Sequential APAAR IDs (possible fabricated records)
            ids = sorted(int(r["apaar_id"]) for r in rows if r["apaar_id"].isdigit())
            seq = sum(1 for x, y in zip(ids, ids[1:]) if y - x == 1)
            if len(ids) >= 10 and seq / (len(ids) - 1) > 0.3:
                out.append({"type": "SEQUENTIAL_APAAR_IDS", "severity": "high", "institution": inst,
                            "detail": f"{seq} consecutive APAAR ID pairs - IDs look generated, not issued"})

    # 4. Same person under different APAAR IDs (identity reuse)
    ident = defaultdict(set)
    inst_of = {}
    for r in conn.execute("SELECT s.apaar_id, s.name, s.dob, i.name inst FROM students s JOIN institutions i ON i.id=s.institution_id"):
        k = (norm(r["name"]), r["dob"])
        ident[k].add(r["apaar_id"])
        inst_of[k] = r["inst"]
    for (nm, dob), ids in ident.items():
        if len(ids) > 1 and nm:
            out.append({"type": "IDENTITY_REUSE", "severity": "high", "institution": inst_of[(nm, dob)],
                        "detail": f"Name '{nm}' with DOB {dob} appears under {len(ids)} different APAAR IDs"})

    # 5. Multi-institution enrolment
    for r in conn.execute("""SELECT apaar_id, academic_year, COUNT(DISTINCT institution_id) n,
                             GROUP_CONCAT(DISTINCT i.name) names FROM students s
                             JOIN institutions i ON i.id=s.institution_id WHERE enrol_status='active'
                             GROUP BY apaar_id, academic_year HAVING n>1"""):
        out.append({"type": "MULTI_INSTITUTION_ENROLMENT", "severity": "high", "institution": r["names"],
                    "detail": f"APAAR ...{r['apaar_id'][-4:]} enrolled in {r['n']} institutions for {r['academic_year']}"})

    # 6. High rejection rate
    for u in util:
        tot = conn.execute("SELECT COUNT(*) c FROM students WHERE institution_id=?", (u["id"],)).fetchone()["c"]
        if tot >= 10 and u["flagged"] / tot > 0.25:
            out.append({"type": "HIGH_ERROR_RATE", "severity": "medium", "institution": u["name"],
                        "detail": f"{u['flagged']} of {tot} records ({100 * u['flagged'] / tot:.0f}%) are flagged or rejected"})
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(out, key=lambda x: order[x["severity"]])
