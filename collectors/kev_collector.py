import requests

from Database.database import update_kev_status


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def get_kev_data():

    print("Fetching CISA KEV data...")

    try:
        response = requests.get(
            KEV_URL,
            timeout=30
        )

    except requests.RequestException as error:

        print("Error connecting to CISA:", error)

        return []

    if response.status_code != 200:

        print("Failed to fetch CISA KEV data.")

        print(
            "HTTP Status:",
            response.status_code
        )

        return []

    data = response.json()

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    return vulnerabilities


if __name__ == "__main__":

    vulnerabilities = get_kev_data()

    print(
        f"Total KEV vulnerabilities: "
        f"{len(vulnerabilities)}"
    )

    kev_cve_ids = []

    for vulnerability in vulnerabilities:

        cve_id = vulnerability.get("cveID")

        if cve_id:

            kev_cve_ids.append(cve_id)

    if kev_cve_ids:

        update_kev_status(
            kev_cve_ids
        )

        print(
            "KEV data updated successfully!"
        )

    else:

        print(
            "No KEV CVE IDs were found."
        )