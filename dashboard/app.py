from flask import Flask, render_template, request, abort
import sqlite3


app = Flask(__name__)

DATABASE_NAME = "vulnradar.db"


def get_database():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def dashboard():

    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "").strip()
    kev = request.args.get("kev", "").strip()

    connection = get_database()

    # =====================================================
    # STATISTICS
    # =====================================================

    total_cves = connection.execute("""
        SELECT COUNT(*)
        FROM cves
    """).fetchone()[0]

    critical_cves = connection.execute("""
        SELECT COUNT(*)
        FROM cves
        WHERE severity = 'CRITICAL'
    """).fetchone()[0]

    high_cves = connection.execute("""
        SELECT COUNT(*)
        FROM cves
        WHERE severity = 'HIGH'
    """).fetchone()[0]

    kev_cves = connection.execute("""
        SELECT COUNT(*)
        FROM cves
        WHERE is_kev = 1
    """).fetchone()[0]

    total_news = connection.execute("""
        SELECT COUNT(*)
        FROM news
    """).fetchone()[0]

    average_cvss = connection.execute("""
        SELECT AVG(cvss_score)
        FROM cves
        WHERE cvss_score IS NOT NULL
    """).fetchone()[0]

    average_cvss = round(average_cvss or 0, 2)

    highest_risk = connection.execute("""
        SELECT MAX(risk_score)
        FROM cves
    """).fetchone()[0]

    highest_risk = highest_risk or 0

    # =====================================================
    # ALERTS
    # =====================================================

    alerts = connection.execute("""
        SELECT
            cve_id,
            cvss_score,
            severity,
            is_kev,
            risk_score,
            priority
        FROM cves
        WHERE priority IN ('CRITICAL', 'HIGH')
        ORDER BY
            is_kev DESC,
            risk_score DESC
        LIMIT 10
    """).fetchall()

    # =====================================================
    # SEVERITY CHART
    # =====================================================

    severity_data = connection.execute("""
        SELECT severity, COUNT(*) AS count
        FROM cves
        GROUP BY severity
    """).fetchall()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for row in severity_data:

        if row["severity"]:

            name = row["severity"].upper()

            if name in severity_counts:
                severity_counts[name] = row["count"]

    # =====================================================
    # KEV CHART
    # =====================================================

    kev_data = connection.execute("""
        SELECT is_kev, COUNT(*) AS count
        FROM cves
        GROUP BY is_kev
    """).fetchall()

    kev_yes = 0
    kev_no = 0

    for row in kev_data:

        if row["is_kev"] == 1:
            kev_yes = row["count"]
        else:
            kev_no = row["count"]

    # =====================================================
    # RISK CHART
    # =====================================================

    risk_data = connection.execute("""
        SELECT
            CASE
                WHEN risk_score >= 80 THEN 'CRITICAL'
                WHEN risk_score >= 60 THEN 'HIGH'
                WHEN risk_score >= 30 THEN 'MEDIUM'
                ELSE 'LOW'
            END AS risk_level,
            COUNT(*) AS count
        FROM cves
        GROUP BY risk_level
    """).fetchall()

    risk_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for row in risk_data:

        if row["risk_level"] in risk_counts:
            risk_counts[row["risk_level"]] = row["count"]

    # =====================================================
    # CVE SEARCH
    # =====================================================

    query = """
        SELECT
            cve_id,
            cvss_score,
            severity,
            is_kev,
            risk_score,
            priority
        FROM cves
        WHERE 1=1
    """

    parameters = []

    if search:

        query += """
            AND cve_id LIKE ?
        """

        parameters.append(
            f"%{search}%"
        )

    if severity:

        query += """
            AND severity = ?
        """

        parameters.append(
            severity.upper()
        )

    if kev == "yes":

        query += """
            AND is_kev = 1
        """

    elif kev == "no":

        query += """
            AND is_kev = 0
        """

    query += """
        ORDER BY risk_score DESC
        LIMIT 50
    """

    top_cves = connection.execute(
        query,
        parameters
    ).fetchall()

    # =====================================================
    # NEWS INTELLIGENCE
    # =====================================================

    news_articles = connection.execute("""
        SELECT
            n.id,
            n.title,
            n.url,
            n.published,
            n.source,

            GROUP_CONCAT(
                DISTINCT nc.cve_id
            ) AS related_cves,

            MAX(c.is_kev) AS has_kev,

            MAX(c.risk_score) AS highest_risk,

            MAX(c.priority) AS highest_priority

        FROM news n

        LEFT JOIN news_cves nc
            ON n.id = nc.news_id

        LEFT JOIN cves c
            ON nc.cve_id = c.cve_id

        GROUP BY n.id

        ORDER BY n.id DESC

        LIMIT 30
    """).fetchall()

    connection.close()

    # =====================================================
    # RENDER
    # =====================================================

    return render_template(
        "index.html",

        total_cves=total_cves,
        critical_cves=critical_cves,
        high_cves=high_cves,
        kev_cves=kev_cves,
        total_news=total_news,
        average_cvss=average_cvss,
        highest_risk=highest_risk,

        alerts=alerts,

        severity_counts=severity_counts,

        kev_yes=kev_yes,
        kev_no=kev_no,

        risk_counts=risk_counts,

        top_cves=top_cves,

        news_articles=news_articles,

        search=search,
        severity=severity,
        kev=kev
    )


# =========================================================
# CVE DETAILS
# =========================================================

@app.route("/cve/<cve_id>")
def cve_details(cve_id):

    connection = get_database()

    cve = connection.execute("""
        SELECT
            cve_id,
            description,
            cvss_score,
            severity,
            cwe,
            published,
            last_modified,
            is_kev,
            risk_score,
            priority
        FROM cves
        WHERE cve_id = ?
    """, (cve_id,)).fetchone()

    connection.close()

    if cve is None:
        abort(404)

    return render_template(
        "cve_details.html",
        cve=cve
    )


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )