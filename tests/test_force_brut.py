import pandas as pd

from src.detecteur.force_brut import detect_brute_force


def test_detecte_brute_force():
    # On crée de faux logs de connexion
    df = pd.DataFrame(
        {
            "timestamp": [
                "2026-01-01 10:00:00",
                "2026-01-01 10:01:00",
                "2026-01-01 10:02:00",
                "2026-01-01 10:03:00",
                "2026-01-01 10:04:00",
            ],
            "source_ip": [
                "192.168.1.10",
                "192.168.1.10",
                "192.168.1.10",
                "192.168.1.10",
                "192.168.1.10",
            ],
            "action": [
                "login",
                "login",
                "login",
                "login",
                "login",
            ],
            "status": [
                "failed",
                "failed",
                "failed",
                "failed",
                "failed",
            ],
        }
    )

    alertes = detect_brute_force(df)

    # On attend une seule alerte
    assert len(alertes) == 1

    # On vérifie le type de l'alerte
    assert alertes[0].alert_type == "brute_force"

    # On vérifie l'IP détectée
    assert alertes[0].source_ip == "192.168.1.10"

    # On vérifie la gravité
    assert alertes[0].severity == "high"