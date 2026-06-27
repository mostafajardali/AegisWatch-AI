"""
Ce fichier contient les fonctions qui permettent à Python
de communiquer avec la base de données PostgreSQL.
"""

import os
from pathlib import Path

import pandas as pd
import psycopg
from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
}

def load_logs() -> pd.DataFrame:
    """
    Charge tous les logs PostgreSQL dans un DataFrame Pandas.
    """

    query = """
        SELECT
            id,
            event_timestamp AS timestamp,
            source_ip,
            username,
            action,
            status,
            endpoint,
            user_agent,
            bytes_sent,
            country,
            label,
            attack_type,
            notes
        FROM logs
        ORDER BY event_timestamp;
    """

    try:
        with psycopg.connect(**DB_CONFIG) as connection:
            with connection.cursor() as cursor:
                cursor.execute(query)

                rows = cursor.fetchall()
                columns = [column.name for column in cursor.description]

    except psycopg.Error as error:
        raise RuntimeError(
            f"Impossible de lire les logs depuis PostgreSQL : {error}"
        ) from error

    return pd.DataFrame(rows, columns=columns)


def make_alert_key(alert) -> str:
    """
    Crée une clé stable pour reconnaître la même alerte.
    """

    data = "|".join(
        [
            alert.alert_type,
            alert.source_ip,
            alert.endpoint or "",
            str(alert.first_seen) if alert.first_seen is not None else "",
            str(alert.last_seen) if alert.last_seen is not None else "",
            alert.reason,
        ]
    )

    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def to_python_datetime(value):
    """
    Transforme un timestamp Pandas en datetime Python si nécessaire.
    """

    if value is None:
        return None

    if hasattr(value, "to_pydatetime"):
        return value.to_pydatetime()

    return value


def save_alerts(alerts: list) -> int:
    """
    Sauvegarde les nouvelles alertes dans PostgreSQL.

    Retourne le nombre de nouvelles alertes ajoutées.
    """

    query = """
        INSERT INTO alerts (
            alert_id,
            alert_type,
            severity,
            source_ip,
            endpoint,
            first_seen,
            last_seen,
            event_count,
            risk_score,
            reason,
            mitre_tactic,
            mitre_technique,
            alert_key
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (alert_key) DO NOTHING
        RETURNING alert_id;
    """

    inserted_count = 0

    try:
        with psycopg.connect(**DB_CONFIG) as connection:
            with connection.cursor() as cursor:
                for alert in alerts:
                    cursor.execute(
                        query,
                        (
                            alert.alert_id,
                            alert.alert_type,
                            alert.severity,
                            alert.source_ip,
                            alert.endpoint,
                            to_python_datetime(alert.first_seen),
                            to_python_datetime(alert.last_seen),
                            alert.event_count,
                            alert.risk_score,
                            alert.reason,
                            alert.mitre_tactic,
                            alert.mitre_technique,
                            make_alert_key(alert),
                        ),
                    )

                    # fetchone() donne une valeur seulement si PostgreSQL
                    # a vraiment ajouté une nouvelle ligne.
                    if cursor.fetchone() is not None:
                        inserted_count += 1

            connection.commit()

    except psycopg.Error as error:
        raise RuntimeError(
            f"Impossible de sauvegarder les alertes : {error}"
        ) from error

    return inserted_count

def load_alerts() ->list:
    query = """
        SELECT 
           alert_id,
            alert_type,
            severity,
            source_ip,
            endpoint,
            first_seen,
            last_seen,
            event_count,
            risk_score,
            reason,
            mitre_tactic,
            mitre_technique,
            alert_key,
            status
            FROM alerts;
            
        """
    try:
        with psycopg.connect(**DB_CONFIG) as connection:
            with connection.cursor() as cursor:
                cursor.execute(query)

                rows = cursor.fetchall()
                columns = [column.name for column in cursor.description]

    except psycopg.Error as error:
        raise RuntimeError(
            f"Impossible de lire les alerts depuis PostgreSQL : {error}"
        ) from error

    return pd.DataFrame(rows, columns=columns)
    
    
def update_alert_status(alert_id: str, new_status: str) -> None:
    """
    Modifie le statut d'une alerte dans PostgreSQL.
    """

    allowed_statuses = ["new", "investigating", "resolved"]

    if new_status not in allowed_statuses:
        raise ValueError("Statut invalide.")

    query = """
        UPDATE alerts
        SET status = %s
        WHERE alert_id = %s;
    """

    try:
        with psycopg.connect(**DB_CONFIG) as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, (new_status, alert_id))

            connection.commit()

    except psycopg.Error as error:
        raise RuntimeError(
            f"Impossible de modifier le statut de l'alerte : {error}"
        ) from error

if __name__ == "__main__":
    logs = load_logs()

    print(f"{len(logs)} logs chargés depuis PostgreSQL.")
    print(logs.head())