import requests
from bs4 import BeautifulSoup


def get_news():
    """
    Collect cybersecurity news articles.

    Returns:
        list of dictionaries containing:
        title, url, published, source
    """

    news = []

    sources = [
        {
            "name": "The Hacker News",
            "url": "https://thehackernews.com/"
        },
        {
            "name": "BleepingComputer",
            "url": "https://www.bleepingcomputer.com/"
        }
    ]

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        )
    }

    for source in sources:

        try:
            response = requests.get(
                source["url"],
                headers=headers,
                timeout=15
            )

            response.raise_for_status()

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            # Find links
            links = soup.find_all("a", href=True)

            for link in links:

                title = link.get_text(
                    " ",
                    strip=True
                )

                url = link.get("href")

                if not title or not url:
                    continue

                # Ignore very small/non-article links
                if len(title) < 20:
                    continue

                # Convert relative URLs
                if url.startswith("/"):
                    url = source["url"].rstrip("/") + url

                # Avoid duplicates
                if any(article["url"] == url for article in news):
                    continue

                news.append({
                    "title": title,
                    "url": url,
                    "published": "",
                    "source": source["name"]
                })

                # Limit each source
                if sum(
                    1 for article in news
                    if article["source"] == source["name"]
                ) >= 30:
                    break

            print(
                f"[+] {source['name']}: "
                f"{sum(1 for article in news if article['source'] == source['name'])} "
                "articles collected"
            )

        except requests.RequestException as error:

            print(
                f"[!] Failed to collect "
                f"{source['name']}: {error}"
            )

        except Exception as error:

            print(
                f"[!] Error processing "
                f"{source['name']}: {error}"
            )

    print(
        f"\n[+] Total news articles collected: {len(news)}"
    )

    return news


if __name__ == "__main__":

    articles = get_news()

    print("\nSample articles:\n")

    for article in articles[:5]:

        print(
            f"- {article['title']}"
        )

        print(
            f"  {article['url']}"
        )

        print(
            f"  Source: {article['source']}\n"
        )