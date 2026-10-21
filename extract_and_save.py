import json, datetime, requests
from chrome_real_fetcher import (
    query_omaha,
    download_with_progress,
    extract_chrome_dll,
    extract_salt_from_bytes,
)

CHANNELS = ["stable", "beta", "dev", "canary"]

# Cargar datos anteriores
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

        # Si la versión ya está en el historial, no re-descargamos
        channel_data = results.get(channel, {})
        history      = channel_data.get("history", [])
        known_versions = {e["version"] for e in history}

        if version in known_versions:
            print(f"[=] {channel}: {version} ya registrado, omitiendo")
            continue

        pkg    = download_with_progress(url, session)
        dll    = extract_chrome_dll(pkg)
        result = extract_salt_from_bytes(dll)

        if result:
            salt, _, _ = result
            entry = {"version": version, "salt": salt,
                     "date": datetime.date.today().isoformat()}

            history.insert(0, entry)

            results[channel] = {
                "current": entry,      # acceso rápido al último
                "history": history,    # todos los anteriores
            }
            print(f"[✓] {channel}: {version} → {salt}")

    except Exception as e:
        print(f"[!] {channel}: {e}")

results["updated_at"] = datetime.datetime.utcnow().isoformat() + "Z"

with open("data.json", "w") as f:
    json.dump(results, f, indent=2)
