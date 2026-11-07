"""Convert БДУ ФСТЭК XML snapshot to a SQLite database with FTS5 index.

Output: ``data/bdu.sqlite`` (unversioned) and ``data/bdu.sqlite.gz`` (committed).

Threats (БнД УБИ) are loaded from the FSTEC ``thrlist.xlsx`` export
(requires the ``openpyxl`` package); pass ``--no-xlsx`` to build a
vulnerabilities-only database.

Usage:
    python scripts/build_db.py --xml data/vulxml.xml.gz \
                               --xlsx data/thrlist.xlsx \
                               --db data/bdu.sqlite \
                               --snapshot-date 2026-04-18
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import shutil
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path


SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE vulnerabilities (
    rowid            INTEGER PRIMARY KEY,
    id               TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    description      TEXT,
    software_names   TEXT,
    vendors          TEXT,
    cves_joined      TEXT,     -- space-joined CVE ids for FTS
    severity         TEXT,
    severity_level   INTEGER,   -- 1 низкий, 2 средний, 3 высокий, 4 критический
    cvss_score       REAL,
    cvss_vector      TEXT,
    identify_date    TEXT,
    publication_date TEXT,
    last_upd_date    TEXT,
    identify_year    INTEGER,
    solution         TEXT,
    status           TEXT,
    exploit_status   TEXT,
    fix_status       TEXT,
    has_exploit      INTEGER NOT NULL DEFAULT 0,
    has_fix          INTEGER NOT NULL DEFAULT 0,
    sources          TEXT
);

CREATE INDEX idx_vul_severity ON vulnerabilities(severity_level);
CREATE INDEX idx_vul_cvss     ON vulnerabilities(cvss_score);
CREATE INDEX idx_vul_year     ON vulnerabilities(identify_year);

-- Composite covering indexes for the hot filter path:
-- year + cvss + severity are the three commonly combined predicates.
-- Leading column must be filtered; SQLite can then use the trailing column
-- for the ORDER BY cvss_score DESC without a separate sort step.
CREATE INDEX idx_vul_year_cvss     ON vulnerabilities(identify_year, cvss_score DESC);
CREATE INDEX idx_vul_severity_cvss ON vulnerabilities(severity_level, cvss_score DESC);
CREATE INDEX idx_vul_cvss_year     ON vulnerabilities(cvss_score DESC, identify_year);

CREATE TABLE cves (
    bdu_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    PRIMARY KEY (bdu_id, cve_id)
);
CREATE INDEX idx_cves_cve ON cves(cve_id);

CREATE TABLE software (
    bdu_id  TEXT NOT NULL,
    name    TEXT,
    vendor  TEXT,
    version TEXT
);
CREATE INDEX idx_software_vendor ON software(vendor COLLATE NOCASE);
CREATE INDEX idx_software_name   ON software(name COLLATE NOCASE);
CREATE INDEX idx_software_bdu    ON software(bdu_id);

CREATE TABLE cwes (
    bdu_id TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    PRIMARY KEY (bdu_id, cwe_id)
);

CREATE TABLE threats (
    rowid           INTEGER PRIMARY KEY,
    id              TEXT NOT NULL UNIQUE,   -- УБИ.1
    num             INTEGER NOT NULL,       -- 1
    name            TEXT NOT NULL,
    description     TEXT,
    source          TEXT,     -- источник угрозы (потенциал нарушителя)
    object          TEXT,     -- объект воздействия
    confidentiality INTEGER NOT NULL DEFAULT 0,
    integrity       INTEGER NOT NULL DEFAULT 0,
    availability    INTEGER NOT NULL DEFAULT 0,
    added_date      TEXT,     -- DD.MM.YYYY
    last_upd_date   TEXT,
    status          TEXT,     -- Опубликована / Архивная
    remarks         TEXT
);
CREATE INDEX idx_thr_status ON threats(status);
CREATE INDEX idx_thr_num    ON threats(num);

CREATE VIRTUAL TABLE vulnerabilities_fts USING fts5(
    name, description, software_names, vendors, cves_joined,
    content = "vulnerabilities",
    content_rowid = "rowid",
    tokenize = "unicode61 remove_diacritics 2"
);

CREATE VIRTUAL TABLE threats_fts USING fts5(
    name, description, source, object,
    content = "threats",
    content_rowid = "rowid",
    tokenize = "unicode61 remove_diacritics 2"
);

CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# thrlist.xlsx header row: exact FSTEC column titles → threats table columns.
THR_COLUMNS = {
    "идентификатор уби": "num",
    "наименование уби": "name",
    "описание": "description",
    "источник угрозы (характеристика и потенциал нарушителя)": "source",
    "объект воздействия": "object",
    "нарушение конфиденциальности": "confidentiality",
    "нарушение целостности": "integrity",
    "нарушение доступности": "availability",
    "дата включения угрозы в бнд уби": "added_date",
    "дата последнего изменения данных": "last_upd_date",
    "статус угрозы": "status",
    "замечания": "remarks",
}

# Max rows scanned while looking for the header line (a merged banner row
# precedes it, and FSTEC occasionally pads the top of the sheet).
THR_HEADER_SCAN_ROWS = 5


def _thr_date(value: object) -> str:
    """Normalize a cell that should hold a date into DD.MM.YYYY."""
    if isinstance(value, dt.datetime):
        return value.strftime("%d.%m.%Y")
    if isinstance(value, dt.date):
        return value.strftime("%d.%m.%Y")
    return str(value).strip() if value is not None else ""


def _thr_text(value: object) -> str:
    """String cell cleanup: FSTEC exports encode CR/LF as ``_x000D_``/``_x000A_``
    literals, which sit next to real newlines — drop them."""
    text = str(value) if value is not None else ""
    return text.replace("_x000D_", "").replace("_x000A_", "\n").strip()


def _thr_flag(value: object) -> int:
    return 1 if value in (1, True, "1", "да", "Да") else 0


def parse_threats(xlsx_path: Path) -> list[tuple]:
    """Read the БнД УБИ export and return rows for the ``threats`` table."""
    try:
        from openpyxl import load_workbook
    except ImportError as exc:  # pragma: no cover - environment issue
        raise SystemExit(
            f"--xlsx needs the openpyxl package (pip install openpyxl): {exc}"
        ) from exc

    wb = load_workbook(xlsx_path, read_only=True, data_only=True)
    ws = wb.active

    header_row_idx = None
    columns: dict[str, int] = {}
    for i, row in enumerate(
        ws.iter_rows(max_row=THR_HEADER_SCAN_ROWS, values_only=True), start=1
    ):
        titles = [
            str(cell).strip().lower() if cell is not None else "" for cell in row
        ]
        matched = {
            THR_COLUMNS[t]: idx
            for idx, t in enumerate(titles)
            if t in THR_COLUMNS
        }
        if "num" in matched and "name" in matched:
            header_row_idx = i
            columns = matched
            break
    if header_row_idx is None:
        wb.close()
        raise SystemExit(f"No УБИ header row found in {xlsx_path}")

    rows: list[tuple] = []
    for row in ws.iter_rows(min_row=header_row_idx + 1, values_only=True):
        cell = lambda key: row[columns[key]] if key in columns else None  # noqa: E731
        num = cell("num")
        name = cell("name")
        if num is None or not str(name or "").strip():
            continue
        rows.append(
            (
                f"УБИ.{int(num)}",
                int(num),
                _thr_text(name),
                _thr_text(cell("description")),
                _thr_text(cell("source")),
                _thr_text(cell("object")),
                _thr_flag(cell("confidentiality")),
                _thr_flag(cell("integrity")),
                _thr_flag(cell("availability")),
                _thr_date(cell("added_date")),
                _thr_date(cell("last_upd_date")),
                _thr_text(cell("status")),
                _thr_text(cell("remarks")),
            )
        )
    wb.close()
    return rows

SEVERITY_MAP = {
    "критический": 4,
    "высокий": 3,
    "средний": 2,
    "низкий": 1,
}


def severity_level(text: str) -> int:
    t = (text or "").lower()
    for keyword, level in SEVERITY_MAP.items():
        if keyword in t:
            return level
    return 0


def parse_year(date_str: str) -> int | None:
    if not date_str:
        return None
    parts = date_str.strip().split(".")
    if len(parts) == 3:
        try:
            return int(parts[2])
        except ValueError:
            return None
    return None


def _text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def build_db(
    xml_path: Path, db_path: Path, snapshot_date: str, xlsx_path: Path | None = None
) -> tuple[int, int]:
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)

    opener = gzip.open if xml_path.suffix == ".gz" else open
    with opener(xml_path, "rb") as fh:
        tree = ET.parse(fh)
    root = tree.getroot()

    total = 0
    vul_rows: list[tuple] = []
    software_rows: list[tuple] = []
    cve_rows: list[tuple] = []
    cwe_rows: list[tuple] = []
    fts_rows: list[tuple] = []

    for vul in root.findall("vul"):
        bdu_id = _text(vul.find("identifier"))
        if not bdu_id:
            continue
        name = _text(vul.find("name"))
        description = _text(vul.find("description"))
        severity = _text(vul.find("severity"))
        cvss_el = vul.find("cvss/vector")
        cvss_score: float | None = None
        cvss_vector = ""
        if cvss_el is not None:
            raw = (cvss_el.get("score") or "").replace(",", ".").strip()
            try:
                cvss_score = float(raw) if raw else None
            except ValueError:
                cvss_score = None
            cvss_vector = _text(cvss_el)

        identify_date = _text(vul.find("identify_date"))
        publication_date = _text(vul.find("publication_date"))
        last_upd_date = _text(vul.find("last_upd_date"))
        solution = _text(vul.find("solution"))
        status = _text(vul.find("vul_status"))
        exploit_status = _text(vul.find("exploit_status"))
        fix_status = _text(vul.find("fix_status"))
        sources = _text(vul.find("sources"))
        has_exploit = 1 if "существует" in exploit_status.lower() else 0
        # БДУ пишет «Уязвимость устранена» / «Информация об устранении отсутствует».
        fix_lower = fix_status.lower()
        has_fix = 1 if ("устранена" in fix_lower or "имеется" in fix_lower) else 0

        software_names: list[str] = []
        vendors: list[str] = []
        for soft in vul.findall("vulnerable_software/soft"):
            sn = _text(soft.find("name"))
            sv = _text(soft.find("vendor"))
            svv = _text(soft.find("version"))
            if sn:
                software_names.append(sn)
            if sv:
                vendors.append(sv)
            software_rows.append((bdu_id, sn, sv, svv))

        seen_cves: set[str] = set()
        cves_for_vul: list[str] = []
        for ident in vul.findall("identifiers/identifier"):
            if ident.get("type", "").upper() == "CVE" and ident.text:
                cve = ident.text.strip().upper()
                if cve and cve not in seen_cves:
                    cve_rows.append((bdu_id, cve))
                    cves_for_vul.append(cve)
                    seen_cves.add(cve)

        vul_rows.append(
            (
                bdu_id,
                name,
                description,
                " ".join(software_names),
                " ".join(vendors),
                " ".join(cves_for_vul),
                severity,
                severity_level(severity),
                cvss_score,
                cvss_vector,
                identify_date,
                publication_date,
                last_upd_date,
                parse_year(identify_date),
                solution,
                status,
                exploit_status,
                fix_status,
                has_exploit,
                has_fix,
                sources,
            )
        )

        seen_cwes: set[str] = set()
        for cwe_ident in vul.findall("cwes/cwe/identifier"):
            if cwe_ident.text:
                cwe = cwe_ident.text.strip()
                if cwe and cwe not in seen_cwes:
                    cwe_rows.append((bdu_id, cwe))
                    seen_cwes.add(cwe)

        total += 1

    conn.executemany(
        """INSERT INTO vulnerabilities
           (id, name, description, software_names, vendors, cves_joined,
            severity, severity_level, cvss_score, cvss_vector,
            identify_date, publication_date, last_upd_date, identify_year,
            solution, status, exploit_status, fix_status, has_exploit, has_fix, sources)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        vul_rows,
    )
    conn.executemany(
        "INSERT INTO software (bdu_id, name, vendor, version) VALUES (?,?,?,?)",
        software_rows,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO cves (bdu_id, cve_id) VALUES (?,?)",
        cve_rows,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO cwes (bdu_id, cwe_id) VALUES (?,?)",
        cwe_rows,
    )
    # Rebuild FTS5 from content table
    conn.execute("INSERT INTO vulnerabilities_fts(vulnerabilities_fts) VALUES('rebuild')")
    conn.execute("INSERT INTO vulnerabilities_fts(vulnerabilities_fts) VALUES('optimize')")

    threat_total = 0
    if xlsx_path is not None:
        thr_rows = parse_threats(xlsx_path)
        conn.executemany(
            """INSERT INTO threats
               (id, num, name, description, source, object,
                confidentiality, integrity, availability,
                added_date, last_upd_date, status, remarks)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            thr_rows,
        )
        conn.execute("INSERT INTO threats_fts(threats_fts) VALUES('rebuild')")
        conn.execute("INSERT INTO threats_fts(threats_fts) VALUES('optimize')")
        threat_total = len(thr_rows)

    conn.execute(
        "INSERT INTO metadata(key, value) VALUES ('snapshot_date', ?)",
        (snapshot_date,),
    )
    conn.execute(
        "INSERT INTO metadata(key, value) VALUES ('total', ?)",
        (str(total),),
    )
    conn.execute(
        "INSERT INTO metadata(key, value) VALUES ('threats_total', ?)",
        (str(threat_total),),
    )
    conn.execute(
        "INSERT INTO metadata(key, value) VALUES ('schema_version', '4')",
    )
    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    return total, threat_total


def gzip_file(src: Path, dst: Path) -> None:
    with open(src, "rb") as fin, gzip.open(dst, "wb", compresslevel=9) as fout:
        shutil.copyfileobj(fin, fout)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml", type=Path, default=Path("data/vulxml.xml.gz"))
    parser.add_argument(
        "--xlsx",
        type=Path,
        default=Path("data/thrlist.xlsx"),
        help="thrlist.xlsx with БнД УБИ threats (skipped if missing).",
    )
    parser.add_argument(
        "--no-xlsx",
        action="store_true",
        help="Do not load threats even if the xlsx file exists.",
    )
    parser.add_argument("--db", type=Path, default=Path("data/bdu.sqlite"))
    parser.add_argument(
        "--snapshot-date",
        required=True,
        help="Snapshot date in YYYY-MM-DD format (date of last mirror refresh).",
    )
    parser.add_argument(
        "--no-gzip",
        action="store_true",
        help="Do not produce bdu.sqlite.gz alongside the raw file.",
    )
    args = parser.parse_args()

    xlsx_path = None
    if not args.no_xlsx:
        if args.xlsx.exists():
            xlsx_path = args.xlsx
        else:
            print(f"Warning: {args.xlsx} not found, building without threats.")

    total, threat_total = build_db(args.xml, args.db, args.snapshot_date, xlsx_path)
    size_mb = args.db.stat().st_size / 1e6
    print(
        f"Built {args.db}: {total} vulnerabilities, "
        f"{threat_total} threats, {size_mb:.1f} MB"
    )

    if not args.no_gzip:
        gz_path = args.db.with_suffix(args.db.suffix + ".gz")
        gzip_file(args.db, gz_path)
        gz_size = gz_path.stat().st_size / 1e6
        print(f"Compressed to {gz_path}: {gz_size:.1f} MB")


if __name__ == "__main__":
    main()
