import sqlite3


DATABASE_NAME = "vulnradar.db"


# =========================================================
# CALCULATE RISK SCORE
# =========================================================

def calculate_risk(cvss_score, is_kev, severity):
    """
    Calculate VulnRadar risk score from 0-100.
    """

    score = 0

    # -----------------------------------------------------
    # CVSS CONTRIBUTION
    # -----------------------------------------------------

    if cvss_score is not None:

        score += (float(cvss_score) / 10) * 60

    # -----------------------------------------------------
    # KEV CONTRIBUTION
    # -----------------------------------------------------

    if is_kev:

        score += 25

    # -----------------------------------------------------
    # SEVERITY CONTRIBUTION
    # -----------------------------------------------------

    severity = (severity or "").upper()

    if severity == "CRITICAL":
        score += 15

    elif severity == "HIGH":
        score += 10

    elif severity == "MEDIUM":
        score += 5

    # -----------------------------------------------------
    # LIMIT SCORE
    # -----------------------------------------------------

    score = min(round(score), 100)

    return score


# =========================================================
# ASSIGN PRIORITY
# =========================================================

def get_priority(risk_score):

    if risk_score >= 80:
        return "CRITICAL"

    elif risk_score >= 60:
        return "HIGH"

    elif risk_score >= 30:
        return "MEDIUM"

    else:
        return "LOW"


# =========================================================
# PROCESS ALL CVEs
# =========================================================

def update_all_risks():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            cve_id,
            cvss_score,
            severity,
            is_kev
        FROM cves
    """)

    cves = cursor.fetchall()

    print()
    print("=" * 50)
    print("VULNRADAR RISK ENGINE")
    print("=" * 50)

    updated = 0

    for cve in cves:

        cve_id = cve[0]
        cvss_score = cve[1]
        severity = cve[2]
        is_kev = cve[3]

        # Calculate risk
        risk_score = calculate_risk(
            cvss_score,
            is_kev,
            severity
        )

        # Calculate priority
        priority = get_priority(
            risk_score
        )

        # Update database
        cursor.execute("""
            UPDATE cves
            SET
                risk_score = ?,
                priority = ?
            WHERE cve_id = ?
        """, (
            risk_score,
            priority,
            cve_id
        ))

        updated += cursor.rowcount

        print(
            f"{cve_id} | "
            f"CVSS: {cvss_score} | "
            f"KEV: {'YES' if is_kev else 'NO'} | "
            f"Risk: {risk_score} | "
            f"Priority: {priority}"
        )

    connection.commit()
    connection.close()

    print()
    print("=" * 50)
    print(f"CVEs analyzed: {len(cves)}")
    print(f"CVEs updated: {updated}")
    print("=" * 50)


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    update_all_risks()