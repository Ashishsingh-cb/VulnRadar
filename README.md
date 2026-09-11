# 🛡️ VulnRadar

VulnRadar is a cybersecurity vulnerability intelligence and risk
prioritization platform built with Python and Flask.

It collects vulnerability information, tracks CISA Known Exploited
Vulnerabilities (KEV), analyzes cybersecurity news, calculates risk
scores, and presents the results through a web dashboard.

---

## 🚀 Features

- 🔎 CVE vulnerability collection
- 🛡️ CISA KEV tracking
- 📰 Cybersecurity news collection
- 🔗 News-to-CVE correlation
- 📊 CVSS-based vulnerability analysis
- 🎯 Risk scoring
- 🚨 Vulnerability priority classification
- 🔍 CVE search and filtering
- 📈 Security analytics dashboard
- 🔄 Automated vulnerability update pipeline
- 💾 SQLite database
- 🌐 Flask web application

---

## 🏗️ Architecture

```text
CVE Sources
     │
     ▼
CVE Collector
     │
     ▼
SQLite Database ◄──── CISA KEV
     │
     ▼
News Scraper
     │
     ▼
News → CVE Correlation
     │
     ▼
Risk Engine
     │
     ▼
Risk Score + Priority
     │
     ▼
Flask Dashboard

🛠️ Technologies
Python
Flask
SQLite
Requests
BeautifulSoup
HTML/CSS
REST/API data sources
Cybersecurity vulnerability intelligence


📂 Project Structure
VulnRadar/
│
├── collectors/
│   ├── cve_collector.py
│   ├── kev_collector.py
│   ├── news_collector.py
│   └── news_scraper.py
│
├── processors/
│   └── news_processor.py
│
├── intelligence/
│   └── risk_engine.py
│
├── Database/
│   └── database.py
│
├── dashboard/
│   ├── app.py
│   └── templates/
│
├── tests/
│
├── update_vulnradar.py
├── requirements.txt
├── .gitignore
└── README.md


⚙️ Installation

Clone the repository:
git clone YOUR_REPOSITORY_URL
cd VulnRadar

Create a virtual environment:
python -m venv venv

Activate it on Windows:
venv\Scripts\activate

Install dependencies:
pip install -r requirements.txt

▶️ Running VulnRadar

Run the update pipeline:
python update_vulnradar.py

Start the dashboard:
python -m dashboard.app

Open:
http://127.0.0.1:5000/


📊 Dashboard

The dashboard provides:

Total CVEs
Critical vulnerabilities
CISA KEV vulnerabilities
Security news count
CVSS information
Risk scores
Vulnerability priority
Search and filtering
CVE details

🎯 Risk Prioritization

VulnRadar combines vulnerability information and exploitation
indicators to help prioritize vulnerabilities.

Each vulnerability receives:

Risk Score
     ↓
Priority
     ↓
LOW / MEDIUM / HIGH / CRITICAL

This allows security teams to focus on vulnerabilities that require
greater attention.

🔐 Cybersecurity Purpose

VulnRadar is designed as a learning and portfolio project demonstrating
concepts including:

Vulnerability management
CVE analysis
Threat intelligence
Risk prioritization
Security automation
Web application development
Security data processing

📌 Future Improvements
Automated scheduled updates
More threat-intelligence sources
Advanced news-to-CVE correlation
Email/security alerts
Export reports
Authentication
More advanced risk scoring
Docker deployment


👨‍💻 AUTHOR 

Ashish Singh
Cybersecurity Student

## 📸 Screenshots

### VulnRadar Dashboard

<img width="1894" height="952" alt="image" src="https://github.com/user-attachments/assets/5dc75fb2-1fa7-4722-9996-ae52829b9e10" />
<img width="1633" height="806" alt="image" src="https://github.com/user-attachments/assets/be93be0e-9912-404e-808e-7f750a1de114" />

