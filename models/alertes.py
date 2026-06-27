"""
Ce fichier définit le modèle Alert.

Une alerte représente une activité suspecte détectée par le système,
par exemple une attaque brute force, un abus d'API ou une exfiltration
de données.

Toutes les alertes utilisent la même structure afin de pouvoir être
affichées, enregistrées plus tard dans une base de données et envoyées
via une API.
"""

from dataclasses import dataclass, field, asdict, fields
from datetime import datetime
from uuid import uuid4
import pandas as pd

@dataclass
class Alert:
    #champs obligatoire:
    alert_type: str
    severity: str #niveau de gravité
    source_ip: str
    reason: str
    mitre_tactic: str
    mitre_technique: str
    
    # Champs avec valeurs par défaut:
    alert_id: str = field(default_factory=lambda: str(uuid4()))
    endpoint: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0
    risk_score: int = 0
    
    #tranformer une alerte en dictionnaire
    def to_dict(self) -> dict:
        return asdict(self)
    @classmethod
    #retourne le nom des champs
    def columns(cls) -> list[str]:
        return [f.name for f in fields(cls)]


def alerts_to_dataframe(alerts: list[Alert]) -> pd.DataFrame:
    return pd.DataFrame(
            [alert.to_dict() for alert in alerts],
            columns=Alert.columns()
        )
    