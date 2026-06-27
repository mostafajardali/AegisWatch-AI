"""
Ce détecteur recherche les tentatives de connexion répétées.

Une alerte est créée lorsqu'une même adresse IP effectue plusieurs
échecs de connexion dans une courte période de temps.

Ce comportement peut indiquer une attaque par force brute.
"""

import pandas as pd
from pathlib import Path
import sys
ROOT_DIR = Path(__file__).resolve().parents[2]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
from models.alertes import Alert
from src.core.config import (
    BRUTE_FORCE_FAILED_ATTEMPTS_THRESHOLD,
    BRUTE_FORCE_WINDOW,
)
DATA_PATH = "data/cyberai_watch_logs_start.csv"

def detect_brute_force(df: pd.DataFrame) -> list[Alert]:
    alerts = []
    df=df.copy()
    #trier selon le temps
    df["timestamp"]=pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")
    
    #creation d'une nouvelle data avec les login
    login_df = df[df["action"] == "login"].copy()
    
    for ip, group in login_df.groupby("source_ip"):
        failed = group[group["status"] == "failed"].copy()
        failed_indexing=failed.set_index("timestamp")
        cpt5min = failed_indexing["status"].rolling(
        BRUTE_FORCE_WINDOW,
        closed="both"
        ).count()
        print(cpt5min)
        #si le nombre d'essai(failed) plus grand de 5
        if (cpt5min >= BRUTE_FORCE_FAILED_ATTEMPTS_THRESHOLD).any():
            max_essais=int(cpt5min.max())
            dernier_moment = cpt5min.idxmax()
            debut_fenetre = dernier_moment - pd.Timedelta(BRUTE_FORCE_WINDOW)
            events_suspects = failed[
            (failed["timestamp"] >= debut_fenetre) &
            (failed["timestamp"] <= dernier_moment)
            ]
            alerts.append(
                Alert(
                alert_type="brute_force",
                severity="high",
                source_ip=ip,
                endpoint=None,
                first_seen=events_suspects["timestamp"].min(),
                last_seen=events_suspects["timestamp"].max(),
                event_count=len(events_suspects),
                risk_score=min(100, max_essais * 15),
                reason=f"{max_essais} failed login attempts within 5 minutes",
                mitre_tactic="Credential Access",
                mitre_technique="T1110 - Brute Force",
            ))
    return alerts



if __name__ == "__main__":
    df = pd.read_csv(DATA_PATH)
    print(detect_brute_force(df))
