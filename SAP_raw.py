#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SAP Security Notes Collector
- Scrapes recent + archive advisories (web)
- Imports PDF-based advisories from CSV/Excel
- Stores into PostgreSQL staging table
"""

import os
import sys
import subprocess
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
import re
import psycopg2
import json
import logging
from dotenv import load_dotenv
import pandas as pd
from psycopg2.extras import Json
import argparse

# =========================
# Dependencies Auto-install
# =========================
required_modules = ["requests", "bs4", "psycopg2", "python-dotenv", "pandas", "openpyxl"]
for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", module])

# -------------------------
# Logging
# -------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("sap_collector")

# -------------------------
# Load Env + DB Config
# -------------------------
load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "sap"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "623809"),
    "port": int(os.getenv("DB_PORT", 5432)),
}
TABLE_NAME = "staging_table"

# -------------------------
# Regex + Helpers
# -------------------------
release_date_regex = re.compile(r"On (\d{1,2})(?:st|nd|rd|th)? of (\w+) (\d{4})")

def clean_text(text):
    return ' '.join(text.split()).strip()

def parse_cvss_vector(url):
    return urlparse(url).fragment if url else ""

def parse_release_date(text):
    m = release_date_regex.search(text)
    if m:
        day, month_name, year = m.groups()
        try:
            return datetime.strptime(f"{day} {month_name} {year}", "%d %B %Y").date()
        except:
            return None
    return None

# -------------------------
# DB Setup
# -------------------------
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
        logger.info(f"✅ Table '{TABLE_NAME}' is ready.")
    except Exception as e:
        logger.error(f"❌ Error creating table: {e}")
    finally:
        if conn:
            conn.close()

def insert_raw(data_dict):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        cur.execute(
            f"""INSERT INTO {TABLE_NAME} 
                (vendor_name, source_url, raw_data) 
                VALUES (%s, %s, %s)
                ON CONFLICT (source_url) DO NOTHING;""",
            ("SAP", data_dict.get("source_url"), json.dumps(data_dict, ensure_ascii=False))
        )

        conn.commit()
        cur.close()
    except Exception as e:
        logger.error(f"❌ Insert failed for {data_dict.get('note_id')}: {e}")
    finally:
        if conn:
            conn.close()

# -------------------------
# Scrape Recent Advisories
# -------------------------
def scrape_recent():
    BASE_URL = "https://support.sap.com"
    INDEX_URL = f"{BASE_URL}/en/my-support/knowledge-base/security-notes-news.html?anchorId=section"

    soup = BeautifulSoup(requests.get(INDEX_URL).text, "html.parser")
    month_links = [BASE_URL + a.get("href") for a in soup.select("div.panelWrapper a")
                   if a.get("href") and "/security-notes-news" in a.get("href")]
    logger.info(f"🔍 Found {len(month_links)} month links (recent)")

    for link in month_links:
        soup_month = BeautifulSoup(requests.get(link).text, "html.parser")

        release_date = None
        for div in soup_month.select("div.text-editor.content-alignment-start, div.content-width-large"):
            for sup in div.select("sup"):
                sup.decompose()
            for p in div.find_all("p"):
                release_date = parse_release_date(p.get_text(" ", strip=True))
                if release_date:
                    break
            if release_date:
                break

        month_str = link.split("/")[-1].replace(".html", "")
        rows = soup_month.select("table tr")[1:]

        for r in rows:
            cols = r.find_all("td")
            if len(cols) < 3:
                continue

            note_id = clean_text(cols[0].get_text())
            title = clean_text(cols[1].get_text())
            priority = clean_text(cols[2].get_text())

            cvss_score, cvss_vector = None, None
            if len(cols) > 3:
                a_tag = cols[3].find("a")
                if a_tag:
                    cvss_score = clean_text(a_tag.get_text())
                    cvss_vector = parse_cvss_vector(a_tag.get("href"))

            all_cves = re.findall(r"CVE-\d{4}-\d{4,}", title)
            cve_id = all_cves[0] if all_cves else None
            related_cves = all_cves[1:] if len(all_cves) > 1 else []

            data = {
                "note_id": note_id,
                "cve_id": cve_id,
                "release_date": str(release_date) if release_date else None,
                "title": title,
                "priority": priority,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "source_type": "recent",
                "related_cves": related_cves,
                "month": month_str,
                "source_url": f"{link}#{note_id}"
            }
            insert_raw(data)
    logger.info("✅ Recent advisories stored")

# -------------------------
# Scrape Archive Advisories
# -------------------------
def scrape_archive():
    BASE_URL = "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html?anchorId=section_370125364"
    BASE_DOMAIN = "https://support.sap.com"

    res = requests.get(BASE_URL)
    soup = BeautifulSoup(res.text, "html.parser")
    tag = soup.find("a", title="SAP Security Patch Day Bulletin Archive")
    archive_url = urljoin(BASE_DOMAIN, tag.get("href")) if tag else None
    if not archive_url:
        logger.warning("⚠️ Archive link not found.")
        return

    div = BeautifulSoup(requests.get(archive_url).text, "html.parser").find("div", class_="content-width-large")
    html_links = [urljoin(BASE_DOMAIN, a.get("href")) for a in div.find_all("a", title=lambda x: x and "Patch Day Bulletin Archive" in x)
                  if not a.get("href").lower().endswith(".pdf")]
    logger.info(f"🔍 Found {len(html_links)} archive bulletin links")

    for link in html_links:
        soup_page = BeautifulSoup(requests.get(link).text, "html.parser")

        for h2 in soup_page.find_all("h2"):
            month = clean_text(h2.get_text().replace("SAP Security Patch Day – ", ""))
            release_date = None
            p_tag = h2.find_next("p")
            while p_tag:
                release_date = parse_release_date(p_tag.get_text())
                if release_date:
                    break
                p_tag = p_tag.find_next("p")

            table = h2.find_next("table")
            if not table:
                continue
            tbody = table.find("tbody")
            if not tbody:
                continue

            for tr in tbody.find_all("tr"):
                cols = tr.find_all("td")
                if len(cols) < 4:
                    continue

                note_id = clean_text(cols[0].get_text())
                title = clean_text(cols[1].get_text())
                priority = clean_text(cols[2].get_text())

                cvss_a = cols[3].find("a")
                cvss_score = clean_text(cvss_a.get_text()) if cvss_a else ""
                cvss_vector = parse_cvss_vector(cvss_a.get("href")) if cvss_a else ""

                cve_links = [a.get_text(strip=True) for a in cols[1].find_all("a") if "cve.org" in a.get("href", "")]
                cve_id = cve_links[0] if cve_links else None
                related_cves = cve_links[1:] if len(cve_links) > 1 else []

                data = {
                    "note_id": note_id,
                    "cve_id": cve_id,
                    "release_date": str(release_date) if release_date else None,
                    "title": title,
                    "priority": priority,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "source_type": "archive",
                    "related_cves": related_cves,
                    "month": month,
                    "source_url": f"{link}#{note_id}"
                }
                insert_raw(data)
    logger.info("✅ Archive advisories stored")

# -------------------------
# Import from CSV/Excel (PDF sources)
# -------------------------
def normalize_json(record):
    normalized = {
        "note_id": str(record.get("note_id") or "").strip() or None,
        "cve_id": str(record.get("cve_id") or "").strip() or None,
        "release_date": None,
        "title": re.sub(r"\s+", " ", str(record.get("title") or "").strip()) or None,
        "priority": str(record.get("priority") or "").strip() or None,
        "cvss_score": str(record.get("cvss_score") or "").strip() or None,
        "cvss_vector": str(record.get("cvss_vector") or "").strip() or None,
        "source_type": "pdf",
        "related_cves": record.get("related_cves") if isinstance(record.get("related_cves"), list) else [],
        "month": None,
    }

    rd = record.get("release_date")
    if rd:
        try:
            rd_parsed = pd.to_datetime(str(rd)).date()
            normalized["release_date"] = rd_parsed.isoformat()
            normalized["month"] = rd_parsed.strftime("%B-%Y").lower()
        except:
            pass

    return normalized

def process_data_file(filename, file_type):
    df = pd.read_csv(filename) if file_type == "csv" else pd.read_excel(filename)
    if "raw_data" not in df.columns:
        logger.error("❌ No 'raw_data' column found in input file.")
        return False

    for _, row in df.iterrows():
        try:
            raw_json = row["raw_data"]
            if isinstance(raw_json, str):
                raw_json = json.loads(raw_json)
            normalized = normalize_json(raw_json)
            normalized["source_url"] = f"pdf:{normalized.get('note_id')}"
            insert_raw(normalized)
        except Exception as e:
            logger.error(f"⚠️ Row import failed: {e}")
    logger.info("✅ PDF-based advisories stored")
    return True

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SAP Vulnerability Collector")
    parser.add_argument("--import-file", help="Optional CSV/Excel file with PDF advisories")
    parser.add_argument("--type", choices=["csv", "excel"], default="excel", help="File type if using --import-file")
    args = parser.parse_args()

    ensure_table()
    scrape_recent()
    scrape_archive()

    if args.import_file:
        process_data_file(args.import_file, args.type)

    logger.info("🎉 All advisories collected successfully!")
