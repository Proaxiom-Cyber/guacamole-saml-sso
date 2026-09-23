"""Deploy this service to its recorded Workers Free account. Secrets stay in memory."""
import getpass
import json
from pathlib import Path
import subprocess
import requests

root = Path(__file__).resolve().parent
config = json.loads((root / "deployment.json").read_text())
base = "https://api.cloudflare.com/client/v4/accounts/" + config["worker_account_id"]
secret = subprocess.run(
    ["security", "find-generic-password", "-a", getpass.getuser(), "-s", "8bit/cloudflare/admin", "-w"],
    capture_output=True, text=True, check=True,
).stdout.strip()
headers = {"Authorization": "Bearer " + secret}

def checked(response, label):
    print(label, response.status_code)
    data = response.json()
    if not response.ok or not data.get("success"):
        print("Error codes:", [e.get("code") for e in data.get("errors", [])])
        raise SystemExit(1)
    return data.get("result")

plans = checked(requests.get(base + "/subscriptions", headers=headers, timeout=25), "Check free plan")
if any("workers" in p.get("rate_plan", {}).get("id", "") and "free" not in p.get("rate_plan", {}).get("id", "") for p in plans):
    raise SystemExit("Refusing to deploy to Workers Paid")
url = base + "/workers/scripts/" + config["worker_name"]
existing = requests.get(url, headers=headers, timeout=25)
if existing.status_code not in (200, 404):
    raise SystemExit("Cannot establish existing Worker state")
metadata = {
    "main_module": "worker.mjs", "compatibility_date": "2026-09-14",
    "bindings": [
        {"name": "SESSIONS", "type": "durable_object_namespace", "class_name": "Session"},
        {"name": "CLIENT_ID", "type": "plain_text", "text": config["client_id"]},
        {"name": "ORIGIN", "type": "plain_text", "text": config["origin"]},
        {"name": "SESSION_LIMIT", "type": "ratelimit", "namespace_id": "26091501", "simple": {"limit": 10, "period": 60}},
    ],
    "observability": {"enabled": False}, "logpush": False,
}
if existing.status_code == 404:
    metadata["migrations"] = {"new_tag": "v1", "new_sqlite_classes": ["Session"]}
checked(requests.put(url, headers=headers, files={
    "metadata": (None, json.dumps(metadata), "application/json"),
    "worker.mjs": ("worker.mjs", (root / "worker.mjs").read_bytes(), "application/javascript+module"),
}, timeout=40), "Deploy Worker")
checked(requests.post(url + "/subdomain", headers=headers, json={"enabled": True, "previews_enabled": False}, timeout=25), "Enable service")
