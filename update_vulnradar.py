"""
VulnRadar - Automatic Update Pipeline

Runs the complete vulnerability intelligence pipeline:

1. Create/check database
2. Collect CVEs
3. Collect CISA KEV data
4. Update KEV status
5. Collect cybersecurity news
6. Process News -> CVE relationships
7. Calculate risk scores
"""

from Database.database import (
    create_database,
    insert_cves,
    update_kev_status,
    insert_news
)

from collectors.cve_collector import get_cves

from collectors.kev_collector import get_kev_data

from collectors.news_scraper import get_news

from processors.news_processor import process_news

from intelligence.risk_engine import update_all_risks


def run_pipeline():

    print()
    print("=" * 60)
    print("VULNRADAR UPDATE PIPELINE")
    print("=" * 60)
    print()

    try:

        # =====================================================
        # STEP 1 - DATABASE
        # =====================================================

        print("[1/7] Checking database...")

        create_database()

        print("[+] Database ready")
        print()


        # =====================================================
        # STEP 2 - CVE COLLECTION
        # =====================================================

        print("[2/7] Collecting CVE data...")

        cves = get_cves()

        if cves:

            print(
                f"[+] {len(cves)} CVEs collected"
            )

            insert_cves(cves)

        else:

            print("[!] No CVEs collected")

        print()


        # =====================================================
        # STEP 3 - KEV COLLECTION
        # =====================================================

        print("[3/7] Collecting CISA KEV data...")

        kev_data = get_kev_data()

        kev_ids = []

        if kev_data:

            # Handle different possible return formats
            if isinstance(kev_data, list):

                for item in kev_data:

                    if isinstance(item, str):

                        kev_ids.append(item)

                    elif isinstance(item, dict):

                        cve_id = (
                            item.get("cveID")
                            or item.get("cve_id")
                            or item.get("id")
                        )

                        if cve_id:
                            kev_ids.append(cve_id)

            print(
                f"[+] {len(kev_ids)} KEV CVEs found"
            )

        else:

            print("[!] No KEV data collected")

        print()


        # =====================================================
        # STEP 4 - UPDATE KEV
        # =====================================================

        print("[4/7] Updating KEV status...")

        if kev_ids:

            update_kev_status(kev_ids)

            print(
                f"[+] {len(kev_ids)} KEV IDs processed"
            )

        else:

            print("[!] No KEV IDs to update")

        print()


        # =====================================================
        # STEP 5 - NEWS COLLECTION
        # =====================================================

        print("[5/7] Collecting cybersecurity news...")

        articles = get_news()

        if articles:

            print(
                f"[+] {len(articles)} news articles collected"
            )

            insert_news(articles)

        else:

            print("[!] No news articles collected")

        print()


        # =====================================================
        # STEP 6 - NEWS -> CVE PROCESSING
        # =====================================================

        print("[6/7] Processing News -> CVE relationships...")

        process_news()

        print(
            "[+] News-CVE processing complete"
        )

        print()


        # =====================================================
        # STEP 7 - RISK ENGINE
        # =====================================================

        print("[7/7] Calculating risk scores...")

        update_all_risks()

        print(
            "[+] Risk analysis complete"
        )

        print()


        # =====================================================
        # COMPLETE
        # =====================================================

        print("=" * 60)
        print("VULNRADAR UPDATE COMPLETE")
        print("=" * 60)
        print()

    except Exception as error:

        print()
        print("=" * 60)
        print("PIPELINE ERROR")
        print("=" * 60)
        print()

        print(f"[!] {error}")

        print()

        raise


if __name__ == "__main__":

    run_pipeline()  