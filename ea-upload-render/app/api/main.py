import csv
import hashlib
import io
import os
import uuid
from datetime import datetime
from typing import Dict, List, Tuple

from fastapi import FastAPI, File, UploadFile, Request, HTTPException, Form
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

# -----------------
# Config
# -----------------
RAW_DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not RAW_DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

# Render often provides: postgresql://... ; SQLAlchemy psycopg dialect expects: postgresql+psycopg://...
if RAW_DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = RAW_DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
elif RAW_DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = RAW_DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
else:
    DATABASE_URL = RAW_DATABASE_URL

CONFLICT_WINDOW_DAYS = int(os.environ.get("CONFLICT_WINDOW_DAYS", "60"))
TRUST_X_FORWARDED_FOR = os.environ.get("TRUST_X_FORWARDED_FOR", "true").lower() == "true"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

app = FastAPI(title="EA Household Count Uploader", version="1.0")
templates = Jinja2Templates(directory="templates")

# Serve logo and other assets
app.mount("/static", StaticFiles(directory="templates/static"), name="static")


def api_response(
    ok: bool,
    title: str,
    message: str,
    *,
    level: str = "success",
    summary: Dict | None = None,
    data: Dict | None = None,
    status_code: int = 200,
):
    payload: Dict = {
        "ok": ok,
        "level": level,
        "title": title,
        "message": message,
    }
    if summary is not None:
        payload["summary"] = summary
    if data is not None:
        payload.update(data)
    return JSONResponse(status_code=status_code, content=payload)


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException):
    # Keep errors consistent and user-friendly.
    msg = str(exc.detail) if exc.detail else "Request failed."
    return api_response(False, "Upload error", msg, level="error", status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Request, exc: Exception):
    # Prevent raw stack traces / non-JSON bodies from leaking to the browser.
    return api_response(
        False,
        "Server error",
        "Something went wrong on the server. Please try again. If it persists, contact the administrator.",
        level="error",
        status_code=500,
        data={"debug_hint": exc.__class__.__name__},
    )



# Static assets (logo, css, etc.)
app.mount("/static", StaticFiles(directory="templates/static"), name="static")

# CSV template required columns
REQUIRED_HEADERS = ["NAT_EA_SN", "HOUSEHOLD_COUNT"]

# Resolved identifier names for ea_frame (supports either uppercase-quoted or normal lowercase)
EA_COLS: Dict[str, str] = {}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_source_ip(request: Request) -> str:
    if TRUST_X_FORWARDED_FOR:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


def compute_fingerprint(source_ip: str, user_agent: str) -> str:
    raw = f"{source_ip}|{user_agent}".encode("utf-8", errors="ignore")
    return sha256_hex(raw)


def qident(name: str) -> str:
    """Safely quote an identifier (very conservative)."""
    return '"' + name.replace('"', '""') + '"'


def resolve_ea_frame_identifiers() -> Dict[str, str]:
    """Detect whether ea_frame uses uppercase quoted columns or normal lowercase."""
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'ea_frame'
                """
            )
        ).fetchall()

    existing = {r[0] for r in rows}

    # Prefer exact uppercase columns if present
    if "NAT_EA_SN" in existing and "HOUSEHOLD_COUNT" in existing:
        nat = qident("NAT_EA_SN")
        hh = qident("HOUSEHOLD_COUNT")
        upd_at = qident("HOUSEHOLD_COUNT_UPDATED_AT")
        upd_fp = qident("HOUSEHOLD_COUNT_SOURCE_FINGERPRINT")
        upd_id = qident("HOUSEHOLD_COUNT_LAST_UPLOAD_ID")
    else:
        # Fall back to lowercase (common Postgres behavior when created without quotes)
        nat = "nat_ea_sn"
        hh = "household_count"
        upd_at = "household_count_updated_at"
        upd_fp = "household_count_source_fingerprint"
        upd_id = "household_count_last_upload_id"

    return {
        "NAT": nat,
        "HH": hh,
        "UPD_AT": upd_at,
        "UPD_FP": upd_fp,
        "UPD_ID": upd_id,
        "HAS_UPPER": "NAT_EA_SN" in existing and "HOUSEHOLD_COUNT" in existing,
    }


def ensure_schema():
    """Create upload tracking + staging, and add tracking columns on ea_frame."""
    ddl = """
    CREATE TABLE IF NOT EXISTS upload_log (
      upload_id uuid PRIMARY KEY,
      received_at timestamptz NOT NULL DEFAULT now(),
      file_name text,
      file_sha256 text NOT NULL,
      source_ip text,
      user_agent text,
      source_fingerprint text NOT NULL,
      status text NOT NULL,
      total_rows int DEFAULT 0,
      valid_rows int DEFAULT 0,
      updated_rows int DEFAULT 0,
      skipped_conflicts int DEFAULT 0,
      invalid_rows int DEFAULT 0,
      error_summary text,
      client_name text,
      client_project text,
      collection_date date
    );

    CREATE UNIQUE INDEX IF NOT EXISTS ux_upload_filehash
    ON upload_log(file_sha256);

    CREATE TABLE IF NOT EXISTS staging_hh_update (
      upload_id uuid NOT NULL REFERENCES upload_log(upload_id) ON DELETE CASCADE,
      nat_ea_sn text NOT NULL,
      hh_count integer NOT NULL,
      PRIMARY KEY (upload_id, nat_ea_sn)
    );

    CREATE TABLE IF NOT EXISTS ea_household_count_history (
      id bigserial PRIMARY KEY,
      upload_id uuid NOT NULL REFERENCES upload_log(upload_id) ON DELETE CASCADE,
      nat_ea_sn text NOT NULL,
      household_count integer NOT NULL,
      recorded_at timestamptz NOT NULL DEFAULT now(),
      client_name text,
      client_project text,
      collection_date date,
      source_fingerprint text
    );

    CREATE INDEX IF NOT EXISTS ix_ea_hh_hist_nat_ea_sn
      ON ea_household_count_history(nat_ea_sn);
    CREATE INDEX IF NOT EXISTS ix_ea_hh_hist_upload_id
      ON ea_household_count_history(upload_id);
    """

    with engine.begin() as conn:
        conn.execute(text(ddl))

    # add tracking columns based on resolved identifier casing
    cols = resolve_ea_frame_identifiers()
    alter_sql = f"""
    ALTER TABLE ea_frame
      ADD COLUMN IF NOT EXISTS {cols['UPD_AT']} timestamptz,
      ADD COLUMN IF NOT EXISTS {cols['UPD_FP']} text,
      ADD COLUMN IF NOT EXISTS {cols['UPD_ID']} uuid;
    """
    with engine.begin() as conn:
        conn.execute(text(alter_sql))

    # store globally
    EA_COLS.clear()
    EA_COLS.update(cols)


@app.on_event("startup")
def startup():
    ensure_schema()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "conflict_window_days": CONFLICT_WINDOW_DAYS})


def api_msg(ok: bool, title: str, message: str, *, details: Dict | None = None, status_code: int = 200):
    payload: Dict[str, object] = {"ok": ok, "title": title, "message": message}
    if details is not None:
        payload["details"] = details
    return JSONResponse(payload, status_code=status_code)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Ensure the frontend always gets a friendly JSON message.
    msg = exc.detail if isinstance(exc.detail, str) else "Request failed. Please check your input and try again."
    return api_msg(False, "Upload not completed", msg, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Avoid leaking stack traces to the client.
    return api_msg(False, "Server error", "Something went wrong on the server. Please try again in a moment.")


def parse_and_check_duplicates(file_bytes: bytes) -> Tuple[List[Dict[str, str]], List[str]]:
    try:
        text_data = file_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded")

    f = io.StringIO(text_data)
    reader = csv.DictReader(f)

    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV is empty or missing header row")

    header_set = {h.strip() for h in reader.fieldnames if h}
    for h in REQUIRED_HEADERS:
        if h not in header_set:
            raise HTTPException(status_code=400, detail=f"Missing required column: {h}")

    rows: List[Dict[str, str]] = []
    seen = set()
    dups = set()

    for r in reader:
        nat = (r.get("NAT_EA_SN") or "").strip()
        hh = (r.get("HOUSEHOLD_COUNT") or "").strip()

        if nat:
            if nat in seen:
                dups.add(nat)
            else:
                seen.add(nat)

        rows.append({"NAT_EA_SN": nat, "HOUSEHOLD_COUNT": hh})

    return rows, sorted(list(dups))


def validate_rows(rows: List[Dict[str, str]]) -> Tuple[List[Tuple[str, int]], List[Dict[str, str]]]:
    valids: List[Tuple[str, int]] = []
    invalids: List[Dict[str, str]] = []

    for idx, r in enumerate(rows, start=2):
        nat = (r.get("NAT_EA_SN") or "").strip()
        hh_raw = (r.get("HOUSEHOLD_COUNT") or "").strip()

        if not nat:
            invalids.append({
                "line": str(idx),
                "NAT_EA_SN": nat,
                "HOUSEHOLD_COUNT": hh_raw,
                "error": "NAT_EA_SN is empty",
            })
            continue

        try:
            hh = int(hh_raw)
            if hh < 0:
                raise ValueError("negative")
        except Exception:
            invalids.append({
                "line": str(idx),
                "NAT_EA_SN": nat,
                "HOUSEHOLD_COUNT": hh_raw,
                "error": "HOUSEHOLD_COUNT must be integer >= 0",
            })
            continue

        valids.append((nat, hh))

    return valids, invalids


def nat_keys_exist(nats: List[str]) -> Tuple[List[str], List[str]]:
    if not nats:
        return [], []

    nat_col = EA_COLS["NAT"]

    with engine.begin() as conn:
        res = conn.execute(
            text(f"SELECT {nat_col} FROM ea_frame WHERE {nat_col} = ANY(:nats)"),
            {"nats": nats},
        ).fetchall()

    existing = {row[0] for row in res}
    missing = [n for n in nats if n not in existing]
    return list(existing), missing


@app.get("/template")
def download_template():
    return JSONResponse({"template_csv": "NAT_EA_SN,HOUSEHOLD_COUNT\n"})


@app.post("/upload/hhcount")
async def upload_hhcount(
    request: Request,
    file: UploadFile = File(...),
    client_name: str = Form(...),
    client_project: str = Form(...),
    collection_date: str = Form(...),
):
    # Basic form validation
    client_name = (client_name or "").strip()
    client_project = (client_project or "").strip()
    collection_date = (collection_date or "").strip()

    if not client_name:
        raise HTTPException(status_code=400, detail="Client Name is required")
    if not client_project:
        raise HTTPException(status_code=400, detail="Client Project is required")
    if not collection_date:
        raise HTTPException(status_code=400, detail="Date of Collection is required")

    try:
        collection_dt = datetime.strptime(collection_date, "%Y-%m-%d").date()
    except Exception:
        raise HTTPException(status_code=400, detail="Date of Collection must be in YYYY-MM-DD format")

    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted")

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    max_bytes = int(os.environ.get("MAX_UPLOAD_BYTES", "10485760"))  # 10MB default
    if len(file_bytes) > max_bytes:
        raise HTTPException(status_code=400, detail=f"File too large. Max size is {max_bytes} bytes")

    file_hash = sha256_hex(file_bytes)
    source_ip = get_source_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    fingerprint = compute_fingerprint(source_ip, user_agent)

    upload_id = uuid.uuid4()

    # Idempotency: same file hash should not be processed twice (internet retry/double click)
    with engine.begin() as conn:
        try:
            conn.execute(
                text(
                    """
                    INSERT INTO upload_log (
                      upload_id, file_name, file_sha256, source_ip, user_agent, source_fingerprint,
                      status, client_name, client_project, collection_date
                    )
                    VALUES (
                      :upload_id, :file_name, :file_sha256, :source_ip, :user_agent, :fp,
                      'received', :client_name, :client_project, :collection_date
                    )
                    """
                ),
                {
                    "upload_id": str(upload_id),
                    "file_name": file.filename,
                    "file_sha256": file_hash,
                    "source_ip": source_ip,
                    "user_agent": user_agent,
                    "fp": fingerprint,
                    "client_name": client_name,
                    "client_project": client_project,
                    "collection_date": collection_dt,
                },
            )
        except IntegrityError:
            prev = conn.execute(
                text(
                    """
                    SELECT upload_id, received_at, status, total_rows, valid_rows, updated_rows,
                           skipped_conflicts, invalid_rows, error_summary
                    FROM upload_log
                    WHERE file_sha256 = :h
                    ORDER BY received_at DESC
                    LIMIT 1
                    """
                ),
                {"h": file_hash},
            ).mappings().first()

            return api_response(
                True,
                "Already processed",
                "This exact file was already uploaded earlier, so we did not process it again.",
                level="success",
                data={
                    "file_already_processed": True,
                    "conflict_window_days": CONFLICT_WINDOW_DAYS,
                    "previous_upload": dict(prev) if prev else None,
                },
            )

    # Parse + reject duplicates-in-file
    rows, dup_keys = parse_and_check_duplicates(file_bytes)
    if dup_keys:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE upload_log
                    SET status='rejected',
                        total_rows=:t,
                        invalid_rows=:inv,
                        error_summary=:err
                    WHERE upload_id=:upload_id
                    """
                ),
                {
                    "upload_id": str(upload_id),
                    "t": len(rows),
                    "inv": len(rows),
                    "err": f"Duplicate NAT_EA_SN found in file: {len(dup_keys)} duplicates",
                },
            )

        return api_response(
            False,
            "Duplicate EA IDs detected",
            "Your CSV has repeated NAT_EA_SN values. Please remove duplicates and re-upload.",
            level="error",
            status_code=400,
            data={
                "reason": "duplicate_nat_ea_sn_in_file",
                "duplicate_nat_ea_sn": dup_keys[:2000],
                "conflict_window_days": CONFLICT_WINDOW_DAYS,
            },
        )

    # Validate values
    valid_pairs, invalid_rows = validate_rows(rows)

    # Ensure NAT_EA_SN exists in ea_frame (we do NOT create new EAs)
    nats = [nat for nat, _ in valid_pairs]
    _, missing = nat_keys_exist(nats)
    missing_set = set(missing)

    final_valids = [(nat, hh) for nat, hh in valid_pairs if nat not in missing_set]

    invalid_rows2 = list(invalid_rows)
    for nat in missing:
        invalid_rows2.append({
            "line": "",
            "NAT_EA_SN": nat,
            "HOUSEHOLD_COUNT": "",
            "error": "NAT_EA_SN not found in ea_frame",
        })

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE upload_log
                SET status='validated',
                    total_rows=:t,
                    valid_rows=:v,
                    invalid_rows=:inv
                WHERE upload_id=:upload_id
                """
            ),
            {"upload_id": str(upload_id), "t": len(rows), "v": len(final_valids), "inv": len(invalid_rows2)},
        )

    if not final_valids:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE upload_log
                    SET status='rejected',
                        error_summary='No valid rows to apply'
                    WHERE upload_id=:upload_id
                    """
                ),
                {"upload_id": str(upload_id)},
            )

        return api_response(
            False,
            "No valid rows",
            "We could not find any valid rows to apply. Please check the CSV template and values, then re-upload.",
            level="error",
            status_code=400,
            data={
                "reason": "no_valid_rows",
                "invalid_rows_sample": invalid_rows2[:2000],
                "conflict_window_days": CONFLICT_WINDOW_DAYS,
            },
        )

    # Load into staging
    with engine.begin() as conn:
        values_sql = ", ".join([f"(:upload_id, :nat{i}, :hh{i})" for i in range(len(final_valids))])
        params: Dict[str, object] = {"upload_id": str(upload_id)}
        for i, (nat, hh) in enumerate(final_valids):
            params[f"nat{i}"] = nat
            params[f"hh{i}"] = hh

        conn.execute(text(f"INSERT INTO staging_hh_update (upload_id, nat_ea_sn, hh_count) VALUES {values_sql}"), params)

    nat_col = EA_COLS["NAT"]
    hh_col = EA_COLS["HH"]
    upd_at = EA_COLS["UPD_AT"]
    upd_fp = EA_COLS["UPD_FP"]
    upd_id = EA_COLS["UPD_ID"]

    # Record every submitted value into history (audit trail), even if it becomes a conflict.
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO ea_household_count_history (
                  upload_id, nat_ea_sn, household_count, client_name, client_project, collection_date, source_fingerprint
                )
                SELECT :upload_id, nat_ea_sn, hh_count, :client_name, :client_project, :collection_date, :fp
                FROM staging_hh_update
                WHERE upload_id = :upload_id
                """
            ),
            {
                "upload_id": str(upload_id),
                "client_name": client_name,
                "client_project": client_project,
                "collection_date": collection_dt,
                "fp": fingerprint,
            },
        )

    # Cross-client conflict detection within CONFLICT_WINDOW_DAYS (Policy A: do NOT overwrite)
    with engine.begin() as conn:
        conflict_rows = conn.execute(
            text(
                f"""
                SELECT s.nat_ea_sn,
                       s.hh_count,
                       e.{hh_col} AS existing_household_count,
                       e.{upd_at} AS household_count_updated_at,
                       e.{upd_fp} AS household_count_source_fingerprint
                FROM staging_hh_update s
                JOIN ea_frame e ON e.{nat_col} = s.nat_ea_sn
                WHERE s.upload_id = :upload_id
                  AND e.{upd_id} IS NOT NULL
                  AND e.{upd_fp} IS DISTINCT FROM :fp
                  AND e.{upd_at} >= now() - interval '{CONFLICT_WINDOW_DAYS} days'
                """
            ),
            {"upload_id": str(upload_id), "fp": fingerprint},
        ).mappings().all()

        conflicts = [dict(r) for r in conflict_rows]

    # Apply updates for non-conflict rows only
    with engine.begin() as conn:
        result = conn.execute(
            text(
                f"""
                UPDATE ea_frame e
                SET {hh_col} = s.hh_count,
                    {upd_at} = now(),
                    {upd_fp} = :fp,
                    {upd_id} = :upload_id
                FROM staging_hh_update s
                WHERE s.upload_id = :upload_id
                  AND e.{nat_col} = s.nat_ea_sn
                  AND NOT (
                    e.{upd_id} IS NOT NULL
                    AND e.{upd_fp} IS DISTINCT FROM :fp
                    AND e.{upd_at} >= now() - interval '{CONFLICT_WINDOW_DAYS} days'
                  );
                """
            ),
            {"upload_id": str(upload_id), "fp": fingerprint},
        )
        updated_rows = int(result.rowcount or 0)

        conn.execute(
            text(
                """
                UPDATE upload_log
                SET status='applied',
                    updated_rows=:u,
                    skipped_conflicts=:s,
                    error_summary=:err
                WHERE upload_id=:upload_id
                """
            ),
            {
                "upload_id": str(upload_id),
                "u": updated_rows,
                "s": len(conflicts),
                "err": None if updated_rows > 0 else "No rows updated (all conflicted or none matched)",
            },
        )

    summary = {
        "total_rows_in_file": len(rows),
        "valid_rows_loaded": len(final_valids),
        "invalid_rows": len(invalid_rows2),
        "updated_rows": updated_rows,
        "skipped_conflicts": len(conflicts),
    }

    if updated_rows > 0 and len(conflicts) == 0 and len(invalid_rows2) == 0:
        msg = "Thank you! Your upload was successful and the EA household counts have been updated."
        level = "success"
        title = "Upload successful"
    elif updated_rows > 0 and (len(conflicts) > 0 or len(invalid_rows2) > 0):
        msg = "Upload completed with some issues: some rows were skipped (conflicts) or invalid. Please review the details below."
        level = "warn"
        title = "Upload completed with warnings"
    else:
        msg = "Your upload was received, but no rows were updated (all rows were in conflict or invalid). Please review the details below."
        level = "warn"
        title = "No updates applied"

    return api_response(
        True,
        title,
        msg,
        level=level,
        summary=summary,
        data={
            "upload_id": str(upload_id),
            "file_already_processed": False,
            "conflict_window_days": CONFLICT_WINDOW_DAYS,
            "invalid_rows_sample": invalid_rows2[:50],
            "conflicts_sample": conflicts[:50],
        },
    )
