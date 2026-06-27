"""
CyberAI Watch est le tableau de bord principal du projet.

Cette application charge les logs de sécurité, lance les détecteurs
de menaces et affiche les alertes trouvées dans une interface Streamlit.
"""

import streamlit as st
import pandas as pd
from pathlib import Path
import sys
ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from models.alertes import alerts_to_dataframe
from src.detecteur.force_brut import detect_brute_force
from src.detecteur.abus_api import detect_abus_api
from src.detecteur.exfiltration_de_donne import detect_exfiltration_de_donnee
from src.database import load_logs,save_alerts,load_alerts,update_alert_status
st.set_page_config(page_title="CyberAI Watch", layout="wide")
st.title("CyberAI Watch - Mini SIEM intelligent")


path = Path("data/cyberai_watch_logs_start.csv")
#voir si le fichier csv existe
try:
    df = load_logs()
except RuntimeError as error:
    st.error(str(error))
    st.stop()
    
#lecture de fichier csv et affichage des donnee
#df = pd.read_csv(path)
st.metric("Nombre de logs", len(df))
st.metric("Evenements attaques", int((df["label"] == "attack").sum()))
st.dataframe(df, use_container_width=True)
#st.bar_chart(df["attack_type"].value_counts())

#Attack
alertes_brute_force = detect_brute_force(df)
alertes_api = detect_abus_api(df)
alertes_exfiltration=detect_exfiltration_de_donnee(df)

toutes_alertes_liste = (
alertes_brute_force
+alertes_api
+alertes_exfiltration
)

toutes_alertes = alerts_to_dataframe(toutes_alertes_liste)
st.subheader("Alertes détectées")
st.metric("Nombre total d'alertes", len(toutes_alertes))

if not toutes_alertes.empty:
    st.warning("ATTENTION : des activités suspectes ont été détectées.")
    st.dataframe(toutes_alertes, use_container_width=True)

    if st.button("Sauvegarder les alertes dans PostgreSQL"):
        try:
            nouvelles_alertes = save_alerts(toutes_alertes_liste)

            if nouvelles_alertes > 0:
                st.success(
                    f"{nouvelles_alertes} nouvelle(s) alerte(s) sauvegardée(s)."
                )
            else:
                st.info(
                    "Aucune nouvelle alerte : elles existent déjà dans PostgreSQL."
                )

        except RuntimeError as error:
            st.error(str(error))

else:
    st.success("Aucune alerte détectée.")
    
#afficher les alerte qui se trouve dans la base
try:
    historique_alertes=load_alerts()
    st.metric("Alerte Historique:", len(historique_alertes))
    st.dataframe(historique_alertes, use_container_width=True)
    st.subheader("Modifier le statut d'une alerte")

    if not historique_alertes.empty:
        # On crée une liste avec les IDs des alertes sauvegardées
        alert_ids = historique_alertes["alert_id"].astype(str).tolist()

        # L'utilisateur choisit une alerte
        selected_alert_id = st.selectbox(
            "Choisir une alerte",
            options=alert_ids,
        )

        # L'utilisateur choisit le nouveau statut
        new_status = st.selectbox(
            "Nouveau statut",
            options=["new", "investigating", "resolved"],
        )

        if st.button("Mettre à jour le statut"):
            try:
                update_alert_status(selected_alert_id, new_status)
                st.success("Statut mis à jour avec succès.")

            except (RuntimeError, ValueError) as error:
                st.error(str(error))
    else:
        st.info("Aucune alerte sauvegardée dans PostgreSQL.")
except RuntimeError as error:
    st.error(str(error))
    
    