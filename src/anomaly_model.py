import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

def train_anomaly_model(df: pd.DataFrame):
    features = ["action", "status", "country", "bytes_sent"]
    X = df[features]
    prep = ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), ["action", "status", "country"]),
        ("num", "passthrough", ["bytes_sent"])
    ])
    model = Pipeline([
        ("prep", prep),
        ("iforest", IsolationForest(contamination=0.08, random_state=42))
    ])
    model.fit(X)
    return model

def score_events(model, df: pd.DataFrame):
    features = ["action", "status", "country", "bytes_sent"]
    df = df.copy()
    df["ai_prediction"] = model.predict(df[features])
    df["ai_label"] = df["ai_prediction"].map({1: "normal", -1: "anomaly"})
    return df
