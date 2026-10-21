import json, datetime, requests
from chrome_real_fetcher import (
    query_omaha,
    download_with_progress,
    extract_chrome_dll,
    extract_salt_from_bytes,
)

CHANNELS = ["stable", "beta", "dev", "canary"]

# Cargar datos anteriores para no perder canales que fallen en esta ejecución
try:
    with open("data.json") as f:
        results = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    results = {}

session = requests.Session()
session.headers["User-Agent"] = "GoogleUpdate/1.3.36.352"

for channel in CHANNELS:
    try:
        version, url = query_omaha(channel)
        if not url:
            print(f"[=] {channel}: sin actualización")
            continue
        pkg    = download_with_progress(url, session)
        dll    = extract_chrome_dll(pkg)
        result = extract_salt_from_bytes(dll)
        if result:
            salt, _, _ = result
            results[channel] = {"version": version, "salt": salt}
            print(f"[✓] {channel}: {version} → {salt}")
    except Exception as e:
        print(f"[!] {channel}: {e}")

results["updated_at"] = datetime.datetime.utcnow().isoformat() + "Z"

with open("data.json", "w") as f:
    json.dump(results, f, indent=2)