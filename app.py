from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import json
import uuid

from sentinelscope.scanners import (
    scan_ports,
    scan_headers,
    discover_private_subnet,
    get_default_port_set,
    validate_private_target,
    validate_private_subnet,
)
from sentinelscope.risk import build_assessment_summary
from sentinelscope.classroom import scan_current_lan, get_classroom_join_link

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
HISTORY_FILE = DATA_DIR / "scan_history.json"

app = Flask(__name__, static_folder="static", static_url_path="")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
CORS(app)

executor = ThreadPoolExecutor(max_workers=4)
jobs = {}
classroom_participants = []


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_history():
    DATA_DIR.mkdir(exist_ok=True)
    if not HISTORY_FILE.exists():
        HISTORY_FILE.write_text("[]", encoding="utf-8")
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def save_history(entry):
    history = load_history()
    history.insert(0, entry)
    HISTORY_FILE.write_text(json.dumps(history[:50], indent=2), encoding="utf-8")


def start_job(job_type, payload, worker):
    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "job_id": job_id,
        "type": job_type,
        "status": "queued",
        "created_at": utc_now(),
        "completed_at": None,
        "payload": payload,
        "result": None,
        "error": None,
    }

    def run():
        jobs[job_id]["status"] = "running"
        try:
            result = worker()
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["completed_at"] = utc_now()
            jobs[job_id]["result"] = result

            save_history({
                "job_id": job_id,
                "type": job_type,
                "created_at": jobs[job_id]["created_at"],
                "completed_at": jobs[job_id]["completed_at"],
                "payload": payload,
                "result": result,
            })
        except Exception as exc:
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["completed_at"] = utc_now()
            jobs[job_id]["error"] = str(exc)

    executor.submit(run)
    return job_id


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/student")
def student_page():
    return send_from_directory("static", "student.html")


@app.route("/api/health")
def health():
    return jsonify({
        "service": "SentinelScope Security Exposure Review Console",
        "status": "healthy",
        "timestamp": utc_now(),
        "safe_mode": "localhost_and_private_networks_only",
    })


@app.route("/api/summary")
def summary():
    history = load_history()
    latest = history[0] if history else None
    return jsonify(build_assessment_summary(history, latest))


@app.route("/api/history")
def history():
    return jsonify(load_history())


@app.route("/api/jobs/<job_id>")
def get_job(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found."}), 404
    return jsonify(job)


@app.route("/api/classroom/link")
def classroom_link():
    return jsonify(get_classroom_join_link())


@app.route("/api/classroom/participants")
def classroom_participant_list():
    return jsonify({
        "count": len(classroom_participants),
        "participants": classroom_participants,
    })


@app.route("/api/classroom/clear", methods=["POST"])
def clear_classroom_participants():
    classroom_participants.clear()
    return jsonify({"status": "cleared"})


@app.route("/api/classroom/register", methods=["POST"])
def classroom_register():
    payload = request.get_json(silent=True) or {}
    name = payload.get("name", "").strip()[:40] or "Student"
    device_type = payload.get("device_type", "").strip()[:40] or "Unknown device"
    has_screen_lock = bool(payload.get("has_screen_lock", False))

    entry = {
        "name": name,
        "device_type": device_type,
        "has_screen_lock": has_screen_lock,
        "joined_at": utc_now(),
        "message": f"I see you, {name}.",
    }

    classroom_participants.insert(0, entry)
    del classroom_participants[50:]

    return jsonify(entry)


@app.route("/api/scan/localhost", methods=["POST"])
def scan_localhost():
    payload = request.get_json(silent=True) or {}
    preset = payload.get("preset", "common")
    ports = get_default_port_set(preset)

    def worker():
        result = scan_ports("127.0.0.1", ports)
        result["assessment"] = build_assessment_summary([{"result": result}], {"result": result})
        return result

    job_id = start_job("localhost_port_scan", {"target": "127.0.0.1", "preset": preset}, worker)
    return jsonify({"job_id": job_id, "status": "queued"})


@app.route("/api/scan/target", methods=["POST"])
def scan_target():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "").strip()
    preset = payload.get("preset", "common")

    resolved = validate_private_target(target)
    ports = get_default_port_set(preset)

    def worker():
        result = scan_ports(resolved["target"], ports, resolved_ip=resolved["resolved_ip"])
        result["assessment"] = build_assessment_summary([{"result": result}], {"result": result})
        return result

    job_id = start_job("private_target_port_scan", {"target": target, "preset": preset}, worker)
    return jsonify({"job_id": job_id, "status": "queued"})


@app.route("/api/scan/headers", methods=["POST"])
def scan_web_headers():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url", "").strip()

    def worker():
        result = scan_headers(url)
        result["assessment"] = build_assessment_summary([{"result": result}], {"result": result})
        return result

    job_id = start_job("web_security_header_scan", {"url": url}, worker)
    return jsonify({"job_id": job_id, "status": "queued"})


@app.route("/api/scan/discovery", methods=["POST"])
def scan_discovery():
    payload = request.get_json(silent=True) or {}
    cidr = payload.get("cidr", "").strip()
    preset = payload.get("preset", "device")

    network = validate_private_subnet(cidr)
    ports = get_default_port_set(preset)

    def worker():
        result = discover_private_subnet(str(network), ports)
        result["assessment"] = build_assessment_summary([{"result": result}], {"result": result})
        return result

    job_id = start_job("private_subnet_device_discovery", {"cidr": cidr, "preset": preset}, worker)
    return jsonify({"job_id": job_id, "status": "queued"})


@app.route("/api/scan/current-lan", methods=["POST"])
def scan_current_network():
    payload = request.get_json(silent=True) or {}
    include_ping = bool(payload.get("include_ping", True))

    def worker():
        result = scan_current_lan(include_ping=include_ping)
        result["assessment"] = build_assessment_summary([{"result": result}], {"result": result})
        return result

    link = get_classroom_join_link()
    job_id = start_job(
        "current_wifi_lan_discovery",
        {
            "detected_local_ip": link.get("local_ip"),
            "mode": "best_effort_ping_dns_arp_tcp_probe",
        },
        worker,
    )

    return jsonify({"job_id": job_id, "status": "queued"})


@app.route("/api/report")
def report():
    history = load_history()
    return jsonify({
        "generated_at": utc_now(),
        "project": "SentinelScope Security Exposure Review Console",
        "safe_demo_boundary": "Designed for owned systems, localhost, private networks, and approved internal reviews only.",
        "summary": build_assessment_summary(history, history[0] if history else None),
        "history": history,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)
