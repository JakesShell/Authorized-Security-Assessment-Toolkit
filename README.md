# SentinelScope Security Exposure Review Console

SentinelScope is a defensive security operations console for authorized exposure review. It helps teams review open services, discover visible devices on private networks, check internal web security headers, and convert findings into a remediation queue.

This project upgrades the original `Authorized-Security-Assessment-Toolkit` into a full Cloud + Security Operations portfolio system with a Flask backend, browser-based dashboard, background scan jobs, current Wi-Fi/LAN discovery, risk scoring, scan history, reporting endpoints, Docker support, and CI validation.

## Overview

SentinelScope is designed to feel like an internal security operations tool used by IT, cloud support, DevOps support, and security operations teams. Instead of leaving assessment results buried in terminal output, the dashboard presents findings through a clean operational console with risk labels, visible device inventory, remediation guidance, and report-ready JSON output.

## Real-World Use Case

Internal support and security teams often need quick answers to questions like:

- Which services are exposed on a private system?
- Which devices are visible on the current private network?
- Which private hosts respond to ping or expose common services?
- Are internal web apps missing important browser security headers?
- Which findings should be handled first?
- Can findings be converted into a practical operational report?

SentinelScope turns those checks into an understandable workflow for review, teaching, and portfolio demonstration.

## Safe Demo Boundary

SentinelScope is built for defensive and authorized use only.

It is intended for:

- Owned systems
- Localhost checks
- Private networks
- Lab environments
- Approved internal reviews
- ICT classroom demonstrations
- Portfolio demonstrations

The application blocks public internet targets by default and focuses on localhost and private network ranges.

## Cloud Relevance

This project connects directly to cloud support, DevOps support, and security operations work because it demonstrates:

- Exposure review thinking
- Service inventory awareness
- Risk prioritization
- Remediation workflows
- Backend API design
- Health and report endpoints
- Docker readiness
- CI validation
- Operational dashboards
- Future fit for cloud asset inventory and AI-assisted recommendations

## Key Features

- Flask backend API
- Polished security operations frontend
- Background scan jobs
- Localhost port scan
- Private target port scan
- Private subnet device discovery
- Current Wi-Fi/LAN discovery
- Best-effort device inventory
- Best-effort hostname, vendor, and device-type guessing
- Internal web security header review
- ICT Classroom Beacon page
- Student opt-in device awareness demo
- Risk scoring
- Remediation queue
- JSON report endpoint
- Scan history persistence
- Dockerfile
- docker-compose support
- GitHub Actions CI

## ICT Classroom Beacon

SentinelScope includes a classroom-safe student beacon workflow.

Students can open a local classroom link from the same Wi-Fi network and voluntarily submit:

- Name
- Device type
- Whether their device has a PIN, password, fingerprint, or face unlock

The student page then displays a safe confirmation message:

`I see you`

This is useful for teaching:

- How devices appear on a network
- Why network visibility is not the same as device control
- Why screen locks matter
- Why consent matters in cybersecurity
- Why unauthorized scanning or messaging is not acceptable

## Current Wi-Fi / LAN Discovery

The dashboard can scan the current private network used by the teacher or operator laptop.

The scan shows:

- Network range reviewed
- Local teacher/operator IP
- Visible device count
- IP address list
- Best-effort hostname
- Best-effort device type guess
- Best-effort vendor guess
- Open services
- Ping response
- MAC address when visible
- Detection method

Important: The visible device count is best-effort. Some phones and laptops hide from ping, ARP visibility, or service probes. The true router-connected device count may be higher.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health check |
| GET | `/api/summary` | Dashboard summary and exposure score |
| GET | `/api/history` | Recent scan history |
| GET | `/api/jobs/<job_id>` | Background job status |
| POST | `/api/scan/localhost` | Scan localhost ports |
| POST | `/api/scan/target` | Scan a private target |
| POST | `/api/scan/headers` | Review internal web security headers |
| POST | `/api/scan/discovery` | Discover private devices on a selected subnet |
| POST | `/api/scan/current-lan` | Auto-detect and scan the current private LAN/Wi-Fi network |
| GET | `/api/classroom/link` | Get local student beacon link |
| GET | `/api/classroom/participants` | View joined classroom beacon participants |
| POST | `/api/classroom/register` | Register a student beacon response |
| POST | `/api/classroom/clear` | Clear classroom participant list |
| GET | `/api/report` | Export JSON assessment report |

## Tech Stack

- Python
- Flask
- JavaScript
- HTML
- CSS
- Docker
- GitHub Actions

## Run Locally

```powershell
cd "C:\github-audit\Authorized-Security-Assessment-Toolkit"

py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py

