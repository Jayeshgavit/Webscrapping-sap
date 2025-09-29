#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import psycopg2
import re
import json
from datetime import datetime
from dotenv import load_dotenv
import os

# =========================
# Load DB config from .env
# =========================
load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "sap"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "623809"),
    "port": int(os.getenv("DB_PORT", 5432))
}

# =========================
# Table Names
# =========================
TABLE_STAGING = "vendor_staging_table"
TABLE_VENDORS = "vendors"
TABLE_ADVISORIES = "advisories"
TABLE_CVES = "cves"
TABLE_ADVISORY_CVE_MAP = "advisory_cves_map"
TABLE_ADVISORY_PRODUCT_MAP = "cve_product_map"

# =========================
# DB Connection
# =========================
def create_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False
        return conn
    except Exception as e:
        print(f"[DB] Connection error: {e}")
        return None

# =========================
# Table Creation
# =========================
def create_normalized_tables(conn):
    with conn.cursor() as cur:
        # Vendors
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
                vendor_id SERIAL PRIMARY KEY,
                vendor_name TEXT NOT NULL UNIQUE
            );
        """)
        # Advisories
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
                advisory_id TEXT PRIMARY KEY,
                vendor_id INT NOT NULL REFERENCES {TABLE_VENDORS}(vendor_id) ON DELETE CASCADE,
                title TEXT,
                severity TEXT,
                initial_release_date TIMESTAMP,
                latest_update_date TIMESTAMP,
                advisory_url TEXT
            );
        """)
        # CVEs
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
                vendor_id INTEGER NOT NULL REFERENCES {TABLE_VENDORS}(vendor_id) ON DELETE CASCADE,
                cve_id TEXT NOT NULL,
                cwe_id TEXT,
                description TEXT,
                severity TEXT,
                cvss_score NUMERIC(3,1),
                cvss_vector TEXT,
                initial_release_date DATE,
                latest_update_date DATE,
                reference_url TEXT,
                PRIMARY KEY (vendor_id, cve_id)
            );
        """)
        # Advisory -> CVE mapping
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_ADVISORY_CVE_MAP} (
                advisory_id TEXT NOT NULL REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
                vendor_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                PRIMARY KEY (advisory_id, vendor_id, cve_id),
                FOREIGN KEY (vendor_id, cve_id) REFERENCES {TABLE_CVES}(vendor_id, cve_id) ON DELETE CASCADE
            );
        """)
        # Advisory -> Product CPE
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_ADVISORY_PRODUCT_MAP} (
                qs_id SERIAL PRIMARY KEY,
                vendor_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                affected_products_cpe JSONB,
                recommendations TEXT,
                FOREIGN KEY (vendor_id, cve_id) REFERENCES {TABLE_CVES}(vendor_id, cve_id) ON DELETE CASCADE,
                CONSTRAINT cve_product_map_vendor_cve_unique UNIQUE (vendor_id, cve_id)
            );
        """)
        # Add processed flag to staging if missing
        cur.execute(f"""
            ALTER TABLE {TABLE_STAGING}
            ADD COLUMN IF NOT EXISTS processed BOOLEAN DEFAULT FALSE;
        """)
        conn.commit()
        print("[DB] Normalized vendor-aware tables created.")

# =========================
# Helper Functions
# =========================
def clean_title(title: str) -> str:
    if not title:
        return ""
    cleaned = re.split(r"(Product|Products|Library)", title, flags=re.IGNORECASE)[0]
    return cleaned.strip(" :;-")

def extract_product_versions(title: str) -> list:
    pairs = []
    if not title:
        return pairs
    title = title.replace("–", "-").replace("—", "-")
    pattern = re.compile(
        r"(?:Product|Products|Library)\s*-\s*(.*?)(?:,\s*Versions\s*-\s*(.*?))?(?:$|\[CVE|\s*Product|$)",
        re.IGNORECASE
    )
    matches = pattern.findall(title)
    for product, versions in matches:
        product = product.strip() if product else ""
        versions = versions.strip() if versions else ""
        pairs.append(f"Product: {product}, Version: {versions}")
    return pairs

def generate_cpe_entries(product_str: str) -> list:
    cpes = []
    vendor = "sap"
    try:
        product_name_raw = product_str.split(",")[0].split(":")[1].strip()
        product_name = re.sub(r"[^a-z0-9]+", "_", product_name_raw.lower())
    except IndexError:
        product_name = "unknown"

    try:
        versions_str = product_str.split("Version:")[1].strip() if "Version:" in product_str else ""
        tokens = [t.strip() for t in re.split(r",|–|-", versions_str) if t.strip()] if versions_str else ["*"]
    except Exception:
        tokens = ["*"]

    for token in tokens:
        version_clean = token.replace(" ", "_") if token else "*"
        cpe = f"cpe:2.3:a:{vendor}:{product_name}:{version_clean}:*:*:*:*:*:*:*"
        cpes.append(cpe)

    return cpes

def get_vendor_id(conn, vendor_name="SAP") -> int:
    with conn.cursor() as cur:
        cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", (vendor_name,))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute(f"INSERT INTO {TABLE_VENDORS}(vendor_name) VALUES (%s) RETURNING vendor_id", (vendor_name,))
        vendor_id = cur.fetchone()[0]
        conn.commit()
        return vendor_id

# =========================
# Insert Functions
# =========================
def insert_advisory(conn, advisory: dict):
    if not advisory.get("advisory_id"):
        return
    with conn.cursor() as cur:
        cur.execute(f"""
            INSERT INTO {TABLE_ADVISORIES} (
                advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url
            ) VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (advisory_id) DO NOTHING
        """, (
            advisory["advisory_id"],
            advisory.get("vendor_id"),
            advisory.get("title"),
            advisory.get("severity"),
            advisory.get("initial_release_date"),
            None,
            advisory.get("advisory_url")
        ))
        conn.commit()

def insert_cve(conn, cve: dict):
    if not cve.get("cve_id"):
        return
    with conn.cursor() as cur:
        cur.execute(f"""
            INSERT INTO {TABLE_CVES} (
                vendor_id, cve_id, cwe_id, description, severity, cvss_score, cvss_vector,
                initial_release_date, latest_update_date, reference_url
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (vendor_id, cve_id) DO NOTHING
        """, (
            cve.get("vendor_id"),
            cve.get("cve_id"),
            cve.get("cwe_id"),
            cve.get("description"),
            cve.get("severity"),
            cve.get("cvss_score"),
            cve.get("cvss_vector"),
            cve.get("initial_release_date"),
            None,
            cve.get("reference_url")
        ))
        conn.commit()

def insert_advisory_cve_map(conn, advisory_id: str, vendor_id: int, cve_id: str):
    if not advisory_id or not vendor_id or not cve_id:
        return
    with conn.cursor() as cur:
        cur.execute(f"""
            INSERT INTO {TABLE_ADVISORY_CVE_MAP} (advisory_id, vendor_id, cve_id)
            VALUES (%s,%s,%s)
            ON CONFLICT DO NOTHING
        """, (advisory_id, vendor_id, cve_id))
        conn.commit()

def insert_product_cpe(conn, vendor_id: int, cve_id: str, cpe: str):
    if not vendor_id or not cve_id or not cpe:
        return
    with conn.cursor() as cur:
        cur.execute(f"""
            INSERT INTO {TABLE_ADVISORY_PRODUCT_MAP} (vendor_id, cve_id, affected_products_cpe, recommendations)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT (vendor_id, cve_id) DO NOTHING
        """, (vendor_id, cve_id, json.dumps([cpe]), None))
        conn.commit()

# =========================
# Process a single row
# =========================
def process_staging_row(conn, staging_id, raw_json):
    try:
        data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json)
    except Exception:
        return

    vendor_id = get_vendor_id(conn, "SAP")
    cleaned_title = clean_title(data.get("title"))

    # Determine CVEs
    cve_ids = [data.get("cve_id")] + data.get("related_cves", [])

    # Insert CVEs and advisory mapping
    for cve_id in filter(None, cve_ids):
        insert_cve(conn, {
            "vendor_id": vendor_id,
            "cve_id": cve_id,
            "cwe_id": None,
            "description": cleaned_title,
            "severity": data.get("priority"),
            "cvss_score": data.get("cvss_score"),
            "cvss_vector": data.get("cvss_vector"),
            "initial_release_date": data.get("release_date"),
            "reference_url": data.get("advisory_url")
        })

        # Insert advisory
        advisory_id = f"{data.get('note_id')}-{cve_id}" if data.get("note_id") else cve_id
        insert_advisory(conn, {
            "advisory_id": advisory_id,
            "vendor_id": vendor_id,
            "title": cleaned_title,
            "severity": data.get("priority"),
            "initial_release_date": data.get("release_date"),
            "advisory_url": data.get("advisory_url")
        })

        # Map advisory to CVE
        insert_advisory_cve_map(conn, advisory_id, vendor_id, cve_id)

        # Insert Product CPEs
        product_pairs = extract_product_versions(data.get("title"))
        for pair in product_pairs:
            cpes = generate_cpe_entries(pair)
            for cpe in cpes:
                insert_product_cpe(conn, vendor_id, cve_id, cpe)

    # Mark staging row as processed
    with conn.cursor() as cur:
        cur.execute(f"UPDATE {TABLE_STAGING} SET processed=true WHERE staging_id=%s", (staging_id,))
        conn.commit()

# =========================
# Process entire staging table
# =========================
def process_staging_table(conn):
    with conn.cursor() as cur:
        cur.execute(f"SELECT staging_id, raw_data FROM {TABLE_STAGING} WHERE processed=false")
        rows = cur.fetchall()
        print(f"🔍 Found {len(rows)} unprocessed rows in staging")
        for row in rows:
            process_staging_row(conn, row[0], row[1])
    print("✅ All rows processed into normalized tables.")

# =========================
# Main
# =========================
if __name__ == "__main__":
    conn = create_db_connection()
    if conn:
        create_normalized_tables(conn)
        process_staging_table(conn)
        conn.close()
        print("🎉 All advisories, CVEs, and CPE entries inserted successfully!")
