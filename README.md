# Log File Analyzer

A modern web app for analyzing server log files and detecting security threats like brute-force attempts, SQL injection, XSS, directory traversal, suspicious user agents, and more.  
Get instant summary, chart visualization, filtering, and downloadable CSV reports.

---

## Features

- **Upload & Analyze:** Instantly scans `.log` or `.txt` files for security events.
- **Threat Detection:**  
  - Failed logins and brute-force IPs  
  - SQL injection, XSS, directory traversal  
  - Sensitive URL access (e.g. `/admin`, `/wp-login.php`)  
  - Suspicious user agents (e.g. sqlmap, nmap)
- **Visualization:** Severity bar chart (Chart.js).
- **Filter Preview:** Show/hide specific threat types in the log view.
- **CSV Export:** Download a CSV report of findings.
- **Fast, Responsive UI:** React frontend with virtualized preview for large logs.

---

## Getting Started

### 1. Backend Setup

```bash
cd backend
npm install
node server.js
