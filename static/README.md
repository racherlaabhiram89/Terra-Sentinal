# APAAR Student Data Management & Verification Platform (SIH 2026 - 26263)

Institution -> Student Data Upload -> APAAR Validation -> Data Verification -> AICTE Central Repository -> Analytics & Monitoring -> Authorized Verification

## Run
```bash
python -m venv venv
venv\Scripts\activate          # Windows   (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
uvicorn main:app --reload
```
Open http://127.0.0.1:8000 (API docs: http://127.0.0.1:8000/docs).
Demo data is created on first start. Delete `apaar.db` to reset.

| Login | Password | Role |
|---|---|---|
| admin | admin123 | AICTE |
| inst1 ... inst4 | inst123 | Institution |
| employer | emp123 | Employer (needs student consent) |
| regulator | reg123 | Auditor |

## Requirement -> where it is built
1. Secure upload/API by APAAR ID: `POST /api/students`, `/bulk`, `/upload-csv`; ERP integration with `X-API-Key` (admin issues in Intake tab)
2. Fields: intake (courses table), seat_type (supernumerary), nri, oci, foreign_national, nationality, category
3. Validation (`validation.py`): invalid/missing APAAR, registry mismatch, duplicates in file and by student ID, intake exceeded, inconsistent data, cross-institution duplicates
4. Dashboards: Overview tab (AICTE sees all, institutions see own)
5. Verification: `POST /api/verify` with role checks and student consent
6. Verifiable records: `POST /api/records/issue/{id}`, public check at `GET /api/records/check/{token}` (HMAC-signed)
7. Integration: REST API + API keys + registry adapter `GET /api/apaar/lookup/{id}` (mocked)
8. Security: JWT, RBAC, PBKDF2 passwords, Fernet-encrypted email/phone, login lockout, hash-chained audit log, consent log
9. Reports: Reports tab / `GET /api/reports/{kind}?format=csv`
10. Certificate printing: `GET /api/certificate/{id}` returns "APAAR ID: xxxx xxxx xxxx | Student ID: ..."
Anomaly detection (`analytics.py`): excess enrolment, z-score utilisation outliers, placeholder DOB clusters, sequential IDs, identity reuse, multi-institution enrolment, high error rate.

## Before production
Set `APAAR_SECRET`, replace the mock `apaar_registry` with the real APAAR/ABC API, move to PostgreSQL, serve over HTTPS, use DigiLocker/OTP for student consent.
