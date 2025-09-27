#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import argparse
import json
import psycopg2
import pandas as pd
from datetime import datetime
from psycopg2.extras import Json

# =========================
# Database configuration
# =========================
DB_CONFIG = {
    "host": "localhost",
    "dbname": "sap",
    "user": "postgres",
    "password": "623809",
    "port": 5432,
}

TABLE_NAME = "staging_table"

# =========================
# Fixed JSON schema
# =========================
EXPECTED_FIELDS = [
    "note_id",
    "cve_id",
    "release_date",
    "title",
    "priority",
    "advisory_url",
    "cvss_score",
    "cvss_vector",
    "source_vector",   # always "pdf"
    "related_cves",
    "month",
]

# =========================
# Build source_url
# =========================
def build_source_url(note_id: str) -> str:
    """Always build SAP archive-based source_url"""
    return (
        "https://support.sap.com/en/my-support/knowledge-base/"
        f"security-notes-news/security-patch-day-archives.html#{note_id}"
    )

# =========================
# Connect to DB
# =========================
def connect_to_db():
    return psycopg2.connect(**DB_CONFIG)

# =========================
# Ensure staging table
# =========================
def ensure_table():
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
                staging_id SERIAL PRIMARY KEY,
                vendor_name TEXT NOT NULL,
                source_url TEXT NOT NULL UNIQUE,
                raw_data JSONB NOT NULL,
                processed BOOLEAN DEFAULT FALSE,
                processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        cur.close()
    finally:
        if conn:
            conn.close()

# =========================
# Normalize JSON
# =========================
def normalize_json(record):
    """Ensure strict schema with nulls if missing."""
    normalized = {}

    # --- note_id ---
    normalized["note_id"] = str(record.get("note_id")).strip() if record.get("note_id") else None

    # --- cve_id ---
    normalized["cve_id"] = str(record.get("cve_id")).strip() if record.get("cve_id") else None

    # --- release_date + month ---
    rd = record.get("release_date")
    if rd:
        try:
            rd_parsed = pd.to_datetime(str(rd)).date()
            normalized["release_date"] = rd_parsed.isoformat()
            normalized["month"] = rd_parsed.strftime("%B-%Y").lower()
        except Exception:
            normalized["release_date"] = None
            normalized["month"] = None
    else:
        normalized["release_date"] = None
        normalized["month"] = None

    # --- title ---
    title = str(record.get("title") or "").strip()
    title = re.sub(r"\s+", " ", title)
    normalized["title"] = title if title else None

    # --- priority ---
    normalized["priority"] = str(record.get("priority")).strip() if record.get("priority") else None

    # --- advisory_url ---
    adv_url = record.get("advisory_url")
    if not adv_url and normalized["note_id"]:
        adv_url = build_source_url(normalized["note_id"])
    normalized["advisory_url"] = adv_url

    # --- cvss_score ---
    normalized["cvss_score"] = str(record.get("cvss_score")).strip() if record.get("cvss_score") else None

    # --- cvss_vector ---
    normalized["cvss_vector"] = str(record.get("cvss_vector")).strip() if record.get("cvss_vector") else None

    # --- source_vector (forced to pdf) ---
    normalized["source_vector"] = "pdf"

    # --- related_cves ---
    rc = record.get("related_cves")
    if isinstance(rc, list):
        normalized["related_cves"] = rc
    elif isinstance(rc, str) and rc.strip():
        normalized["related_cves"] = [rc.strip()]
    else:
        normalized["related_cves"] = []

    return normalized

def parse_json_for_jsonb(value):
    """Always return a dict with proper schema."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return normalize_json({})

    if isinstance(value, dict):
        return normalize_json(value)

    s = str(value).strip()
    s = s.replace("\x00", " ")
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = re.sub(r"\s+", " ", s)

    try:
        data = json.loads(s)
        return normalize_json(data)
    except Exception:
        return normalize_json({})

# =========================
# Read file
# =========================
def read_file(filename, file_type):
    if file_type == "csv":
        with open(filename, "r", encoding="utf-8") as f:
            sample = f.read(2048)
        delimiter = "," if sample.count(",") >= sample.count(";") else ";"
        print(f"Detected CSV delimiter: '{delimiter}'")
        return pd.read_csv(filename, delimiter=delimiter, encoding="utf-8")
    else:
        return pd.read_excel(filename)

# =========================
# Process Data
# =========================
def process_data_file(filename, file_type):
    conn = connect_to_db()
    ensure_table()
    cur = conn.cursor()

    df = read_file(filename, file_type)
    if "raw_data" not in df.columns:
        print("❌ No 'raw_data' column found in input file.")
        return False

    success, errors = 0, 0
    print(f"\n📊 Processing {len(df)} rows...")

    for row_num, (_, row) in enumerate(df.iterrows(), start=1):
        try:
            raw_json = parse_json_for_jsonb(row["raw_data"])
            note_id = raw_json.get("note_id") or f"row{row_num}"
            src_url = build_source_url(note_id)

            cur.execute(
                f"""
                INSERT INTO {TABLE_NAME} (vendor_name, source_url, raw_data)
                VALUES (%s, %s, %s)
                ON CONFLICT (source_url) DO NOTHING
                """,
                ("SAP", src_url, Json(raw_json)),
            )
            success += 1

            if row_num % 10 == 0:
                print(f"Row {row_num}: ✅ inserted")

        except Exception as e:
            errors += 1
            print(f"⚠️ Row {row_num} insert error: {e}")

    conn.commit()
    cur.close()
    conn.close()

    print("\n📊 IMPORT SUMMARY")
    print(f"✅ Inserted: {success}")
    print(f"⚠️ Errors: {errors}")
    return True

# =========================
# Main
# =========================
if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_file = os.path.join(script_dir, "sap_security_notes_full_title_cleaned.xlsx")

    parser = argparse.ArgumentParser(description="SAP Vulnerability Importer (clean JSONB)")
    parser.add_argument("filename", nargs="?", default=default_file, help="Path to CSV/Excel file")
    parser.add_argument("--type", choices=["csv", "excel"], default="excel", help="File type: csv or excel (default: excel)")
    args = parser.parse_args()

    if not os.path.exists(args.filename):
        print(f"❌ File not found: {args.filename}")
        raise SystemExit(1)

    print("SAP Vulnerability Staging Importer")
    print("🔧 Normalizing raw_data into clean JSONB with strict schema + archive source_url")
    print("=" * 70)

    ok = process_data_file(args.filename, args.type)
    print("\n✅ Import completed successfully!" if ok else "\n❌ Import failed!")
