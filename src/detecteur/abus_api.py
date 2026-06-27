"""
Ce détecteur recherche les abus d'API.

Une alerte est créée lorsqu'une même adresse IP envoie trop de requêtes
vers le même endpoint API dans une courte période de temps.

Ce comportement peut indiquer du scraping, une automatisation abusive
ou une tentative d'attaque contre une API.
"""

import pandas as pd
from models.alertes import Alert
from src.core.config import API_REQUESTS_THRESHOLD, API_ABUSE_WINDOW

DATA_PATH = "data/cyberai_watch_logs_start.csv"

def detect_abus_api(df: pd.DataFrame) -> list[Alert]:
    alerts=[]
    df=df.copy()
    df["timestamp"]=pd.to_datetime(df["timestamp"])
    df=df.sort_values("timestamp")
    api_request=df[df["action"]=="api_request"].copy()
    for (ip,endpoint),group in api_request.groupby(["source_ip","endpoint"]):
        group = group.sort_values("timestamp")
        cpt=group.set_index("timestamp")
        cmpt5min = cpt["status"].rolling(API_ABUSE_WINDOW,closed="both").count()
        max_requests = int(cmpt5min.max())
        if (cmpt5min >= API_REQUESTS_THRESHOLD).any():
            alerts.append(
                Alert(
                    alert_type="api_abuse",
                    severity="high",
                    source_ip=ip,
                    endpoint=endpoint,
                    first_seen=group["timestamp"].min(),
                    last_seen=group["timestamp"].max(),
                    event_count=max_requests,
                    risk_score=min(100, max_requests * 12),
                    reason=f"{max_requests} API requests within 5 minutes",
                    mitre_tactic="Credential Access",
                    mitre_technique="API abuse",
                )
            )
    return alerts

if __name__ == "__main__":
    df = pd.read_csv(DATA_PATH)
    print(detect_abus_api(df))