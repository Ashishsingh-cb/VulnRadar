import re
import sqlite3


DATABASE_NAME = "vulnradar.db"

CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"


def extract_cve_ids(text):
    if not text:
        return []

    cve_ids = re.findall(
        CVE_PATTERN,
        text,
        re.IGNORECASE
    )

    return list(set(cve_ids))


def process_news():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, title, url
        FROM news
    """)

    articles = cursor.fetchall()

    print(f"News articles found: {len(articles)}")

    for article in articles:

        article_id = article[0]
        title = article[1]
        url = article[2]

        cve_ids = extract_cve_ids(title)

        if cve_ids:

            print("\n-----------------------------")
            print("News ID:", article_id)
            print("Title:", title)
            print("URL:", url)
            print("CVE IDs found:", cve_ids)

            for cve_id in cve_ids:

                cursor.execute("""
                    SELECT cve_id, cvss_score, severity, is_kev
                    FROM cves
                    WHERE UPPER(cve_id) = UPPER(?)
                """, (cve_id,))

                cve = cursor.fetchone()

                if cve:

                    print("Matched CVE:", cve[0])
                    print("CVSS:", cve[1])
                    print("Severity:", cve[2])
                    print("KEV:", "YES 🚨" if cve[3] else "NO")

                else:

                    print(
                        "CVE not found in database:",
                        cve_id
                    )

    connection.close()


if __name__ == "__main__":
    process_news()