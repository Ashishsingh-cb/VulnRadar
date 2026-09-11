import re

from collectors.news_scraper import get_news


# =========================================================
# CVE EXTRACTION
# =========================================================

def extract_cves(text):

    """
    Find CVE IDs inside security news text.
    """

    if not text:
        return []

    pattern = r"CVE-\d{4}-\d{4,}"

    cves = re.findall(
        pattern,
        text,
        re.IGNORECASE
    )

    unique_cves = []

    for cve in cves:

        cve = cve.upper()

        if cve not in unique_cves:

            unique_cves.append(cve)

    return unique_cves


# =========================================================
# COLLECT NEWS
# =========================================================

def collect_news():

    print()
    print("=" * 60)
    print("VULNRADAR NEWS COLLECTION")
    print("=" * 60)

    articles = get_news()

    print()
    print(
        f"[+] News articles collected: {len(articles)}"
    )

    return articles


# =========================================================
# FIND CVEs IN NEWS
# =========================================================

def analyze_news(articles):

    print()
    print("=" * 60)
    print("ANALYZING NEWS FOR CVEs")
    print("=" * 60)

    total_cves = 0

    for article in articles:

        title = article.get(
            "title",
            ""
        )

        url = article.get(
            "url",
            ""
        )

        source = article.get(
            "source",
            ""
        )

        published = article.get(
            "published",
            ""
        )

        # Search CVEs in available text
        text = " ".join([
            title,
            url,
            source
        ])

        found_cves = extract_cves(text)

        if not found_cves:
            continue

        total_cves += len(found_cves)

        print()
        print(
            f"News: {title}"
        )

        print(
            f"Source: {source}"
        )

        print(
            f"CVEs: {found_cves}"
        )

    print()
    print("=" * 60)
    print(
        f"CVEs detected in news: {total_cves}"
    )
    print("=" * 60)

    return total_cves


# =========================================================
# MAIN
# =========================================================

def main():

    articles = collect_news()

    analyze_news(articles)


if __name__ == "__main__":

    main()