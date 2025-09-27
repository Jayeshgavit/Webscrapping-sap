

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
import re
import psycopg2
import json

# =========================
# Dependencies Auto-install
# =========================
required_modules = ["requests", "bs4", "psycopg2", "json"]
for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", module])

# ------------------------
# DB Config
# ------------------------
DB_CONFIG = {
    "host": "localhost",
    "dbname": "SAP",
    "user": "postgres",
    "password": "623809",
    "port": 5432
}
STAGING_TABLE = "staging_table"

# ------------------------
# Helpers
# ------------------------
release_date_regex = re.compile(r"On (\d{1,2})(?:st|nd|rd|th)? of (\w+) (\d{4})")

def clean_text(text):
    """Remove excess whitespace and newlines"""
    return ' '.join(text.split()).strip()

def insert_raw(cursor, data_dict):
    """Insert JSON into staging table with exact text"""
    ordered = {
        "note_id": data_dict.get("note_id"),
        "cve_id": data_dict.get("cve_id"),
        "release_date": data_dict.get("release_date"),
        "title": clean_text(data_dict.get("title", "")),
        "priority": data_dict.get("priority"),
        "advisory_url": data_dict.get("month_url"),
        "cvss_score": data_dict.get("cvss_score"),
        "cvss_vector": data_dict.get("cvss_vector"),
        "source_type": data_dict.get("source_type"),
        "related_cves": data_dict.get("related_cves"),
        "month": data_dict.get("month")
    }
    cursor.execute(
        f"INSERT INTO {STAGING_TABLE} (vendor_name, raw_data, procced_at) VALUES (%s, %s, NOW())",
        ("SAP", json.dumps(ordered, indent=2, ensure_ascii=False))
    )

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

# ------------------------
# Database Setup
# ------------------------
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()
cur.execute(f"""
CREATE TABLE IF NOT EXISTS {STAGING_TABLE} (
    staging_id SERIAL PRIMARY KEY,
    vendor_name VARCHAR NOT NULL DEFAULT 'SAP',
    raw_data JSON,
    procced_at TIMESTAMP DEFAULT NOW()
)
""")
conn.commit()

# ------------------------
# Scrape Recent Advisories
# ------------------------
def scrape_recent():
    BASE_URL = "https://support.sap.com"
    INDEX_URL = f"{BASE_URL}/en/my-support/knowledge-base/security-notes-news.html?anchorId=section"

    soup = BeautifulSoup(requests.get(INDEX_URL).text, "html.parser")
    month_links = [BASE_URL + a.get("href") for a in soup.select("div.panelWrapper a")
                   if a.get("href") and "/security-notes-news" in a.get("href")]
    print(f"🔍 Found {len(month_links)} month links (recent)")

    for link in month_links:
        print(f"📅 Processing month: {link}")
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
            cve_id = all_cves[0] if all_cves else "N/A"
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
                "month_url": link
            }
            insert_raw(cur, data)
        conn.commit()
    print("✅ Recent advisories stored")

# ------------------------
# Scrape Archive Advisories
# ------------------------
def scrape_archive():
    BASE_URL = "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html?anchorId=section_370125364"
    BASE_DOMAIN = "https://support.sap.com"

    res = requests.get(BASE_URL)
    soup = BeautifulSoup(res.text, "html.parser")
    tag = soup.find("a", title="SAP Security Patch Day Bulletin Archive")
    archive_url = urljoin(BASE_DOMAIN, tag.get("href")) if tag else None
    if not archive_url:
        print("⚠️ Archive link not found.")
        return

    div = BeautifulSoup(requests.get(archive_url).text, "html.parser").find("div", class_="content-width-large")
    html_links = [urljoin(BASE_DOMAIN, a.get("href")) for a in div.find_all("a", title=lambda x: x and "Patch Day Bulletin Archive" in x)
                  if not a.get("href").lower().endswith(".pdf")]
    print(f"🔍 Found {len(html_links)} archive bulletin links")

    for link in html_links:
        print(f"📖 Scraping archive: {link}")
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
                cve_id = cve_links[0] if cve_links else ""
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
                    "month_url": link
                }
                insert_raw(cur, data)
        conn.commit()
    print("✅ Archive advisories stored")

# ------------------------
# Main
# ------------------------
if __name__ == "__main__":
    scrape_recent()
    scrape_archive()
    cur.close()
    conn.close()
    print("\n🎉 All advisories stored with clean titles + procced_at timestamp!")
