"""
Ce fichier contient les paramètres de détection du projet.

Modifier une valeur ici change le comportement des détecteurs
sans devoir modifier leur logique.
"""

# Brute force
BRUTE_FORCE_FAILED_ATTEMPTS_THRESHOLD = 5
BRUTE_FORCE_WINDOW = "5min"

# Abus API
API_REQUESTS_THRESHOLD = 5
API_ABUSE_WINDOW = "5min"

# Exfiltration de données
EXFILTRATION_THRESHOLD_BYTES = 5 * 1024 * 1024
EXFILTRATION_WINDOW = "10min"