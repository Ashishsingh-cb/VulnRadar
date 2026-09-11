import subprocess
import sys


def run_step(name, command):
    print("\n" + "=" * 60)
    print(f"RUNNING: {name}")
    print("=" * 60)

    result = subprocess.run(
        [sys.executable] + command,
        capture_output=False
    )

    if result.returncode != 0:
        print(f"\n[ERROR] {name} failed.")
        return False

    print(f"\n[OK] {name} completed.")
    return True


def main():

    print("\n")
    print("=" * 60)
    print("              VulnRadar Intelligence Pipeline")
    print("=" * 60)

    steps = [

        (
            "CVE Collector",
            ["-m", "collectors.cve_collector"]
        ),

        (
            "CISA KEV Collector",
            ["-m", "collectors.kev_collector"]
        ),

        (
            "News Collector",
            ["-m", "collectors.news_collector"]
        ),

        (
            "News Processor",
            ["-m", "processors.news_processor"]
        ),

        (
            "Risk Analysis",
            ["-m", "intelligence.risk_engine"]
        ),
    ]

    for name, command in steps:

        success = run_step(name, command)

        if not success:
            print("\nPipeline stopped because of an error.")
            return

    print("\n" + "=" * 60)
    print("       VULNRADAR PIPELINE COMPLETED")
    print("=" * 60)

    print("\nYour data has been:")
    print("  [✓] CVEs collected")
    print("  [✓] KEV status updated")
    print("  [✓] Security news collected")
    print("  [✓] News processed")
    print("  [✓] Risk scores calculated")
    print("  [✓] Database updated")

    print("\nStart the dashboard with:")
    print("  python -m dashboard.app")


if __name__ == "__main__":
    main()