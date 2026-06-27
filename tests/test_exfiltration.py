import pandas as pd

from src.detecteur.exfiltration_de_donne import (
    detect_exfiltration_de_donnee,
)


def test_detecte_exfiltration():
    df = pd.DataFrame(
        {
            "timestamp": [
                "2026-01-01 10:00:00",
                "2026-01-01 10:02:00",
                "2026-01-01 10:04:00",
            ],
            "source_ip": [
                "192.168.1.30",
                "192.168.1.30",
                "192.168.1.30",
            ],
            "bytes_sent": [
                2 * 1024 * 1024,
                2 * 1024 * 1024,
                2 * 1024 * 1024,
            ],
        }
    )

    alertes = detect_exfiltration_de_donnee(df)

    assert len(alertes) == 1
    assert alertes[0].alert_type == "data_exfiltration"
    assert alertes[0].source_ip == "192.168.1.30"
    assert alertes[0].severity == "high"
    assert alertes[0].risk_score > 0