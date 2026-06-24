import pandas as pd

DATA_PATH = "data/cyberai_watch_logs_start.csv"

def detect_brute_force(df: pd.DataFrame) -> pd.DataFrame:
    alerts = []
    df = df.sort_values("timestamp")
    login_df = df[df["action"] == "login"].copy()
    for ip, group in login_df.groupby("source_ip"):
        failed = group[group["status"] == "failed"]
        if len(failed) >= 5:
            alerts.append({
                "type": "Brute force suspected",
                "severity": "High",
                "source_ip": ip,
                "reason": f"{len(failed)} failed login attempts",
                "mitre": "Credential Access / Brute Force"
            })
    return pd.DataFrame(alerts)

if __name__ == "__main__":
    df = pd.read_csv(DATA_PATH)
    print(detect_brute_force(df))
