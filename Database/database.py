import sqlite3


DATABASE_NAME = "vulnradar.db"


def create_database():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    # =========================
    # CVE TABLE
    # =========================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            cwe TEXT,
            published TEXT,
            last_modified TEXT,
            is_kev INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            priority TEXT DEFAULT 'LOW'
        )
    """)

    # =========================
    # NEWS TABLE
    # =========================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS news (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            url TEXT UNIQUE NOT NULL,
            published TEXT,
            source TEXT,
            content TEXT
        )
    """)

    # =========================
    # NEWS-CVE RELATION TABLE
    # =========================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS news_cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            news_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            UNIQUE(news_id, cve_id)
        )
    """)

    connection.commit()

    # =========================
    # DATABASE MIGRATION
    # =========================
    # If the old news table already exists without
    # the "content" column, add it safely.

    cursor.execute("PRAGMA table_info(news)")
    columns = [column[1] for column in cursor.fetchall()]

    if "content" not in columns:
        cursor.execute("""
            ALTER TABLE news
            ADD COLUMN content TEXT
        """)

        print("Added 'content' column to news table.")

    # Check CVE table for newer columns
    cursor.execute("PRAGMA table_info(cves)")
    cve_columns = [column[1] for column in cursor.fetchall()]

    if "risk_score" not in cve_columns:
        cursor.execute("""
            ALTER TABLE cves
            ADD COLUMN risk_score INTEGER DEFAULT 0
        """)

        print("Added 'risk_score' column to cves table.")

    if "priority" not in cve_columns:
        cursor.execute("""
            ALTER TABLE cves
            ADD COLUMN priority TEXT DEFAULT 'LOW'
        """)

        print("Added 'priority' column to cves table.")

    connection.commit()
    connection.close()

    print("VulnRadar database is ready!")


# =========================================================
# INSERT CVEs
# =========================================================

def insert_cves(cves):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    inserted = 0

    for cve in cves:

        cursor.execute("""
            INSERT OR IGNORE INTO cves (
                cve_id,
                description,
                cvss_score,
                severity,
                cwe,
                published,
                last_modified,
                is_kev
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve.get("id"),
            cve.get("description"),
            cve.get("cvss_score"),
            cve.get("severity"),
            cve.get("cwe"),
            cve.get("published"),
            cve.get("last_modified"),
            0
        ))

        inserted += cursor.rowcount

    connection.commit()
    connection.close()

    print(f"{inserted} new CVEs inserted into database.")


# =========================================================
# UPDATE CISA KEV STATUS
# =========================================================

def update_kev_status(kev_cve_ids):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    updated = 0

    for cve_id in kev_cve_ids:

        cursor.execute("""
            UPDATE cves
            SET is_kev = 1
            WHERE cve_id = ?
        """, (cve_id,))

        updated += cursor.rowcount

    connection.commit()
    connection.close()

    print(f"{updated} CVEs marked as KEV.")


# =========================================================
# INSERT NEWS
# =========================================================

def insert_news(articles):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    inserted = 0

    for article in articles:

        cursor.execute("""
            INSERT OR IGNORE INTO news (
                title,
                url,
                published,
                source,
                content
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            article.get("title"),
            article.get("url"),
            article.get("published"),
            article.get("source"),
            article.get("content", "")
        ))

        inserted += cursor.rowcount

    connection.commit()
    connection.close()

    print(f"{inserted} new news articles inserted into database.")


# =========================================================
# LINK NEWS WITH CVE
# =========================================================

def link_news_to_cve(news_id, cve_id):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO news_cves (
            news_id,
            cve_id
        )
        VALUES (?, ?)
    """, (
        news_id,
        cve_id
    ))

    connection.commit()
    connection.close()


# =========================================================
# LINK MULTIPLE CVEs TO NEWS
# =========================================================

def link_news_to_cves(news_id, cve_ids):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    linked = 0

    for cve_id in cve_ids:

        cursor.execute("""
            INSERT OR IGNORE INTO news_cves (
                news_id,
                cve_id
            )
            VALUES (?, ?)
        """, (
            news_id,
            cve_id
        ))

        linked += cursor.rowcount

    connection.commit()
    connection.close()

    return linked


# =========================================================
# UPDATE RISK SCORE
# =========================================================

def update_risk_score(cve_id, risk_score, priority):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE cves
        SET risk_score = ?,
            priority = ?
        WHERE cve_id = ?
    """, (
        risk_score,
        priority,
        cve_id
    ))

    connection.commit()
    connection.close()


# =========================================================
# GET ALL CVEs
# =========================================================

def get_all_cves():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM cves
        ORDER BY risk_score DESC
    """)

    cves = cursor.fetchall()

    connection.close()

    return cves


# =========================================================
# GET ALL NEWS
# =========================================================

def get_all_news():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM news
        ORDER BY published DESC
    """)

    news = cursor.fetchall()

    connection.close()

    return news


# =========================================================
# GET NEWS FOR A CVE
# =========================================================

def get_news_for_cve(cve_id):
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT news.*
        FROM news
        JOIN news_cves
            ON news.id = news_cves.news_id
        WHERE news_cves.cve_id = ?
        ORDER BY news.published DESC
    """, (cve_id,))

    news = cursor.fetchall()

    connection.close()

    return news


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    create_database()