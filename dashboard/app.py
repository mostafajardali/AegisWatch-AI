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
from src.m1.anomaly_model import train_anomaly_model, score_events
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

# -------------------------------------------------
# Analyse IA : détection d'anomalies
# -------------------------------------------------
st.divider()
st.subheader("Analyse IA des anomalies")

# Pour cette première version, on entraîne l'IA
# uniquement avec les logs connus comme normaux.
if "label" not in df.columns:
    st.warning(
        "La colonne 'label' est absente : "
        "impossible d'entraîner le modèle IA."
    )

else:
    labels = (
        df["label"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    normal_logs = df[labels == "normal"].copy()

    if normal_logs.empty:
        st.warning(
            "Aucun log marqué 'normal' n'a été trouvé. "
            "L'IA a besoin de logs normaux comme référence."
        )

    else:
        try:
            # 1. L'IA apprend le comportement normal.
            anomaly_model = train_anomaly_model(normal_logs)

            # 2. L'IA analyse tous les logs disponibles.
            logs_with_ai = score_events(anomaly_model, df)

            # 3. On garde uniquement les anomalies.
            anomalies_ai = (
            logs_with_ai[
                logs_with_ai["ai_label"] == "anomaly"
            ]
            .sort_values("ai_score", ascending=False)
            .copy()
            )

            col_ai_1, col_ai_2 = st.columns(2)

            col_ai_1.metric(
                "Anomalies détectées par l'IA",
                len(anomalies_ai),
            )

            col_ai_2.metric(
                "Logs normaux utilisés pour entraîner l'IA",
                len(normal_logs),
            )

            if not anomalies_ai.empty:
                st.warning(
                    "L'IA a détecté des événements inhabituels. "
                    "Ils doivent être vérifiés avant toute action."
                )

                colonnes_ia = [
                    "timestamp",
                    "source_ip",
                    "username",
                    "action",
                    "status",
                    "endpoint",
                    "country",
                    "bytes_sent",
                    "ai_label",
                    "ai_score",
                ]

                affichage_ia = anomalies_ai[colonnes_ia].copy()

                affichage_ia["timestamp"] = pd.to_datetime(
                    affichage_ia["timestamp"],
                    errors="coerce",
                ).dt.strftime("%d/%m/%Y %H:%M:%S")

                affichage_ia["endpoint"] = affichage_ia[
                    "endpoint"
                ].fillna("-")

                affichage_ia = affichage_ia.rename(
                    columns={
                        "timestamp": "Date",
                        "source_ip": "Adresse IP",
                        "username": "Utilisateur",
                        "action": "Action",
                        "status": "Statut",
                        "endpoint": "Endpoint",
                        "country": "Pays",
                        "bytes_sent": "Données envoyées",
                        "ai_label": "Résultat IA",
                        "ai_score": "Score IA / 100",
                    }
                )

                st.dataframe(
                    affichage_ia,
                    use_container_width=True,
                    hide_index=True,
                )

            else:
                st.success(
                    "Aucune anomalie IA détectée dans les logs analysés."
                )

        except (ValueError, KeyError) as error:
            st.error(f"Erreur pendant l'analyse IA : {error}")


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
    colonnes_affichage = [
    "alert_type",
    "severity",
    "source_ip",
    "endpoint",
    "first_seen",
    "last_seen",
    "event_count",
    "risk_score",
    "reason",
    

]
    alertes_affichage = toutes_alertes[colonnes_affichage].copy()
    # On remplace les endpoints vides par un tiret.
    alertes_affichage["endpoint"] = alertes_affichage["endpoint"].fillna("-")

    # On transforme les dates dans un format plus lisible.
    alertes_affichage["first_seen"] = pd.to_datetime(
        alertes_affichage["first_seen"],
        errors="coerce",
    ).dt.strftime("%d/%m/%Y %H:%M:%S")

    alertes_affichage["last_seen"] = pd.to_datetime(
        alertes_affichage["last_seen"],
        errors="coerce",
    ).dt.strftime("%d/%m/%Y %H:%M:%S")

    # On renomme les colonnes pour le dashboard.
    alertes_affichage = alertes_affichage.rename(
        columns={
            "alert_type": "Type",
            "severity": "Gravité",
            "source_ip": "Adresse IP",
            "endpoint": "Endpoint",
            "first_seen": "Première détection",
            "last_seen": "Dernière détection",
            "event_count": "Événements",
            "risk_score": "Score de risque",
            "reason": "Raison",
            "status": "Statut",
        }
    )

    # Affiche uniquement le tableau propre.
    st.dataframe(
        alertes_affichage,
        use_container_width=True,
        hide_index=True,
    )
    

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
    st.subheader("Historique des alertes:")
    #st.dataframe(historique_alertes, use_container_width=True)
    #st.subheader("Modifier le statut d'une alerte")

    if not historique_alertes.empty:
        historique_alertes = historique_alertes.copy()
        #---------
        #compteur des alertes
        #----------
        total_alertes=len(historique_alertes)
        total_new=int((historique_alertes["status"]=="new").sum())
        total_investigating=int((historique_alertes["status"]=="investigating").sum())
        total_resolved=int((historique_alertes["status"]=="resolved").sum())
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total alertes", total_alertes)
        col2.metric("Nouvelles", total_new)
        col3.metric("En investigation", total_investigating)
        col4.metric("Résolues", total_resolved)
        
        ## graphique ------
        # -----------------------------------------
        # Graphique : alertes par type
        # -----------------------------------------
        st.subheader("Alertes par type")

        # Compte automatiquement chaque type d'alerte.
        alertes_par_type = (
            historique_alertes["alert_type"]
            .fillna("inconnu")
            .value_counts()
        )

        # Rend les noms plus faciles à lire.
        alertes_par_type = alertes_par_type.rename(
            {
                "brute_force": "Force brute",
                "api_abuse": "Abus API",
                "data_exfiltration": "Exfiltration de données",
            }
        )

        # Force les nombres à être numériques.
        alertes_par_type = pd.to_numeric(
            alertes_par_type,
            errors="coerce",
        ).fillna(0)

        # Affiche directement la série Pandas.
        st.bar_chart(alertes_par_type, height=300)

        # Affiche le type le plus fréquent.
        nom_type = alertes_par_type.index[0]
        nombre_type = int(alertes_par_type.iloc[0])

        st.caption(
            f"Type le plus fréquent : {nom_type} "
            f"({nombre_type} alerte(s))."
        )
        ##-----------
        
        ##Ip plus suspect
        st.subheader("Adresse IP la plus fréquente")
        alertes_par_ip = (
        historique_alertes["source_ip"]
        .dropna()
        .astype(str)
        .value_counts()
         )
        if not alertes_par_ip.empty:
            ip_plus_frequente = alertes_par_ip.index[0]
            nombre_alertes_ip = int(alertes_par_ip.iloc[0])

            col_ip1, col_ip2 = st.columns(2)

            col_ip1.metric(
                "IP avec le plus d'alertes",
                ip_plus_frequente,
            )

            col_ip2.metric(
                "Nombre d'alertes associées",
                nombre_alertes_ip,
            )

        else:
            st.info("Aucune adresse IP disponible dans les alertes.")
        ##-----------
        
        #----
        #Filtres
        #-----
        st.subheader("Filtres")
        filtre_col1, filtre_col2, filtre_col3, filtre_col4 = st.columns(4)
        # "Tous" signifie : ne pas filtrer cette colonne.
        statut_choisi = filtre_col1.selectbox(
            "Filtrer par statut",
            options=[
                "Tous",
                *sorted(historique_alertes["status"].astype(str).unique().tolist()),
            ],
        )
        gravite_choisie = filtre_col2.selectbox(
            "Filtrer par gravité",
            options=[
                "Tous",
                *sorted(
                    historique_alertes["severity"]
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()
                ),
            ],
        )
        type_choisi = filtre_col3.selectbox(
            "Filtrer par type d'alerte",
            options=[
                "Tous",
                *sorted(
                    historique_alertes["alert_type"]
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()
                ),
            ],
        )
        ip_choisie = filtre_col4.selectbox(
            "Filtrer par adresse IP",
            options=[
                "Tous",
                *sorted(
                    historique_alertes["source_ip"]
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()
                ),
            ],
        )
        # -------------------------------------------------
        # 3. APPLICATION DES FILTRES
        # -------------------------------------------------
        alertes_filtrees = historique_alertes.copy()

        if statut_choisi != "Tous":
            alertes_filtrees = alertes_filtrees[
                alertes_filtrees["status"] == statut_choisi
            ]

        if gravite_choisie != "Tous":
            alertes_filtrees = alertes_filtrees[
                alertes_filtrees["severity"] == gravite_choisie
            ]

        if type_choisi != "Tous":
            alertes_filtrees = alertes_filtrees[
                alertes_filtrees["alert_type"] == type_choisi
            ]

        if ip_choisie != "Tous":
            alertes_filtrees = alertes_filtrees[
                alertes_filtrees["source_ip"].astype(str) == ip_choisie
            ]

        st.caption(
            f"{len(alertes_filtrees)} alerte(s) affichée(s) après filtrage."
        )
        # On choisit uniquement les colonnes utiles pour l'affichage.
        colonnes_affichage = [
            "alert_type",
            "severity",
            "source_ip",
            "endpoint",
            "first_seen",
            "last_seen",
            "event_count",
            "risk_score",
            "reason",
            "status",
        ]

        alertes_affichage = alertes_filtrees[colonnes_affichage].copy()
        # On remplace les endpoints vides par un tiret.
        alertes_affichage["endpoint"] = alertes_affichage["endpoint"].fillna("-")
        # On transforme les dates dans un format plus lisible.
        alertes_affichage["first_seen"] = pd.to_datetime(
            alertes_affichage["first_seen"],
            errors="coerce",
        ).dt.strftime("%d/%m/%Y %H:%M:%S")

        alertes_affichage["last_seen"] = pd.to_datetime(
            alertes_affichage["last_seen"],
            errors="coerce",
        ).dt.strftime("%d/%m/%Y %H:%M:%S")
        alertes_affichage = alertes_affichage.rename(
            columns={
                "alert_type": "Type",
                "severity": "Gravité",
                "source_ip": "Adresse IP",
                "endpoint": "Endpoint",
                "first_seen": "Première détection",
                "last_seen": "Dernière détection",
                "event_count": "Événements",
                "risk_score": "Score de risque",
                "reason": "Raison",
                "status": "Statut",
            }
        )
        st.dataframe(
            alertes_affichage,
            use_container_width=True,
            hide_index=True,
        )
        
        
        #Modification des status
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
    
    