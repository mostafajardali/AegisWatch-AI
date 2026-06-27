import pandas as pd

from src.detecteur.abus_api import detect_abus_api


def test_detecte_abus_api():
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
                "192.168.1.20",
                "192.168.1.20",
                "192.168.1.20",
                "192.168.1.20",
                "192.168.1.20",
            ],
            "action": [
                "api_request",
                "api_request",
                "api_request",
                "api_request",
                "api_request",
            ],
            "status": [
                "success",
                "success",
                "success",
                "success",
                "success",
            ],
            "endpoint": [
                "/api/v1/users",
                "/api/v1/users",
                "/api/v1/users",
                "/api/v1/users",
                "/api/v1/users",
            ],
        }
    )

    alertes = detect_abus_api(df)

    assert len(alertes) == 1
    assert alertes[0].alert_type == "api_abuse"
    assert alertes[0].source_ip == "192.168.1.20"
    assert alertes[0].endpoint == "/api/v1/users"
    assert alertes[0].severity == "high"