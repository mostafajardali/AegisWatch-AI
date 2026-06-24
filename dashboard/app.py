import streamlit as st
import pandas as pd
from pathlib import Path

st.set_page_config(page_title="CyberAI Watch", layout="wide")
st.title("CyberAI Watch - Mini SIEM intelligent")
path = Path("data/cyberai_watch_logs_start.csv")
if not path.exists():
    st.warning("Copiez le fichier CSV dans le dossier data/.")
else:
    df = pd.read_csv(path)
    st.metric("Nombre de logs", len(df))
    st.metric("Evenements attaques", int((df["label"] == "attack").sum()))
    st.dataframe(df, use_container_width=True)
    st.bar_chart(df["attack_type"].value_counts())
