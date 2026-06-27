"""
Ce détecteur recherche une possible exfiltration de données.

Une alerte est créée lorsqu'une même adresse IP envoie un volume important
de données pendant une courte période de temps.

Ce comportement peut indiquer qu'une personne ou un programme essaie
de sortir des données de l'entreprise sans autorisation.
"""

import pandas as pd
from models.alertes import Alert
from src.core.config import (
    EXFILTRATION_THRESHOLD_BYTES,
    EXFILTRATION_WINDOW,
)
DATA_PATH = "data/cyberai_watch_logs_start.csv"

def detect_exfiltration_de_donnee(df: pd.DataFrame) -> list[Alert]:
    alertes=[]
    df=df.copy()
    df["timestamp"]=pd.to_datetime(df["timestamp"])
    df=df.sort_values("timestamp")
    for ip,groupe in df.groupby("source_ip"):
        groupe = groupe.sort_values("timestamp")
        groupe = groupe.set_index("timestamp")
        volume_10min = groupe["bytes_sent"].rolling(EXFILTRATION_WINDOW,closed="both").sum()
        if (volume_10min >= EXFILTRATION_THRESHOLD_BYTES).any():
            max_volume = int(volume_10min.max())

            # Conversion de bytes vers Mo pour un message lisible
            max_volume_mo = max_volume / (1024 * 1024)

            dernier_moment = volume_10min.idxmax()
            debut_fenetre = dernier_moment - pd.Timedelta(EXFILTRATION_WINDOW)

            alertes.append(
                Alert(
                    alert_type="data_exfiltration",
                    severity="high",
                    source_ip=ip,
                    endpoint=None,
                    first_seen=debut_fenetre,
                    last_seen=dernier_moment,
                    event_count=0,
                    risk_score=min(100, int((max_volume / EXFILTRATION_THRESHOLD_BYTES) * 70)),
                    reason=f"{max_volume_mo:.2f} Mo sent within 10 minutes",
                    mitre_tactic="Exfiltration",
                    mitre_technique="Data Exfiltration",
                )
            )
    return alertes
        
if __name__ == "__main__":
    df = pd.read_csv(DATA_PATH)
    print(detect_exfiltration_de_donnee(df))