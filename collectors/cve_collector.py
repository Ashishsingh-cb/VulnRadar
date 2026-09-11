import requests

from Database.database import create_database, insert_cves


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_cves():
    print("Fetching CVE data from NVD...")

    try:
        response = requests.get(NVD_URL, timeout=30)
    except requests.RequestException as error:
        print("Error connecting to NVD:", error)
        return []

    if response.status_code != 200:
        print("Failed to fetch CVE data.")
        print("HTTP Status:", response.status_code)
        return []

    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])

    cves = []

    for item in vulnerabilities:

        cve = item.get("cve", {})

        # -------------------------
        # CVE ID
        # -------------------------

        cve_id = cve.get("id")

        # -------------------------
        # Description
        # -------------------------

        description = ""

        descriptions = cve.get("descriptions", [])

        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # -------------------------
        # Dates
        # -------------------------

        published = cve.get("published")

        last_modified = cve.get("lastModified")

        # -------------------------
        # CVSS
        # -------------------------

        cvss_score = None

        severity = "UNKNOWN"

        metrics = cve.get("metrics", {})

        if "cvssMetricV31" in metrics:

            cvss_data = metrics["cvssMetricV31"][0].get(
                "cvssData", {}
            )

            cvss_score = cvss_data.get("baseScore")

            severity = cvss_data.get(
                "baseSeverity",
                "UNKNOWN"
            )

        elif "cvssMetricV30" in metrics:

            cvss_data = metrics["cvssMetricV30"][0].get(
                "cvssData", {}
            )

            cvss_score = cvss_data.get("baseScore")

            severity = cvss_data.get(
                "baseSeverity",
                "UNKNOWN"
            )

        elif "cvssMetricV2" in metrics:

            cvss_data = metrics["cvssMetricV2"][0].get(
                "cvssData", {}
            )

            cvss_score = cvss_data.get("baseScore")

            severity = "UNKNOWN"

        # -------------------------
        # CWE
        # -------------------------

        cwe = "UNKNOWN"

        weaknesses = cve.get("weaknesses", [])

        for weakness in weaknesses:

            weakness_descriptions = weakness.get(
                "description", []
            )

            for weakness_description in weakness_descriptions:

                if weakness_description.get("lang") == "en":

                    cwe = weakness_description.get(
                        "value",
                        "UNKNOWN"
                    )

                    break

            if cwe != "UNKNOWN":
                break

        # -------------------------
        # Create CVE object
        # -------------------------

        cves.append({
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "cwe": cwe,
            "published": published,
            "last_modified": last_modified
        })

    return cves


if __name__ == "__main__":

    # Make sure database exists
    create_database()

    # Get CVEs
    cves = get_cves()

    print(f"Total CVEs received: {len(cves)}")

    # Save CVEs
    if cves:
        insert_cves(cves)

        print("CVE data saved successfully!")

    else:
        print("No CVE data was collected.")