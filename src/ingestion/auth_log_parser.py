"""
Lit un fichier Linux auth.log et transforme les connexions SSH
en événements compatibles avec CyberAI Watch.
"""

from datetime import datetime
from pathlib import Path
import re

import pandas as pd
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.database import save_logs

# Colonnes attendues par CyberAI Watch.
LOG_COLUMNS = [
    "timestamp",
    "source_ip",
    "username",
    "action",
    "status",
    "endpoint",
    "user_agent",
    "bytes_sent",
    "country",
    "label",
    "attack_type",
    "notes",
]


# Cette expression récupère la date et le message SSH de chaque ligne.
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"(?P<message>.+)$"
)


# Exemple reconnu :
# Failed password for root from 203.0.113.10 port 42102 ssh2
FAILED_LOGIN_PATTERN = re.compile(
    r"^Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\S+) port \d+"
)


# Exemple reconnu :
# Accepted password for alice from 198.51.100.25 port 51200 ssh2
SUCCESS_LOGIN_PATTERN = re.compile(
    r"^Accepted (?:password|publickey) for "
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\S+) port \d+"
)


def parse_auth_log_line(line: str, year: int) -> dict | None:
    """
    Transforme une ligne auth.log en dictionnaire Python.

    Retourne None si la ligne n'est pas une connexion SSH
    réussie ou échouée reconnue.
    """

    line = line.strip()

    # Essaie d'abord de lire la structure générale du log.
    syslog_match = SYSLOG_PATTERN.match(line)

    if syslog_match is None:
        return None

    month = syslog_match.group("month")
    day = syslog_match.group("day")
    clock = syslog_match.group("clock")
    message = syslog_match.group("message")

    # auth.log ne contient généralement pas l'année.
    # Ici, on l'ajoute manuellement.
    timestamp = datetime.strptime(
        f"{year} {month} {day} {clock}",
        "%Y %b %d %H:%M:%S",
    )

    # Cherche un échec de connexion SSH.
    failed_match = FAILED_LOGIN_PATTERN.match(message)

    if failed_match is not None:
        username = failed_match.group("username")
        source_ip = failed_match.group("source_ip")
        status = "failed"

    else:
        # Cherche une connexion SSH réussie.
        success_match = SUCCESS_LOGIN_PATTERN.match(message)

        if success_match is None:
            return None

        username = success_match.group("username")
        source_ip = success_match.group("source_ip")
        status = "success"

    # Le dictionnaire final respecte les colonnes de CyberAI Watch.
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "action": "login",
        "status": status,
        "endpoint": "ssh",
        "user_agent": "sshd",
        "bytes_sent": 0,
        "country": "unknown",
        "label": "unknown",
        "attack_type": "unknown",
        "notes": message,
    }


def parse_auth_log_file(file_path: Path, year: int) -> pd.DataFrame:
    """
    Lit tout le fichier auth.log et retourne un DataFrame Pandas.
    """

    events = []

    with file_path.open(encoding="utf-8", errors="replace") as file:
        for line in file:
            event = parse_auth_log_line(line, year)

            if event is not None:
                events.append(event)

    return pd.DataFrame(events, columns=LOG_COLUMNS)


if __name__ == "__main__":
    # Chemin du dossier principal du projet.
    ROOT_DIR = Path(__file__).resolve().parents[2]

    auth_log_path = ROOT_DIR / "data" / "raw" / "auth.log"

    # Notre fichier de test contient des dates de janvier 2026.
    logs_df = parse_auth_log_file(auth_log_path, year=2026)

    print(f"{len(logs_df)} événement(s) SSH reconnu(s).")

    print(
        logs_df[
            [
                "timestamp",
                "source_ip",
                "username",
                "action",
                "status",
                "endpoint",
            ]
        ].to_string(index=False)
        
    )
    nouveaux_logs = save_logs(logs_df)

    print(
        f"{nouveaux_logs} nouveau(x) log(s) importé(s) "
        "dans PostgreSQL."
    )