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

    # 1 = normal ; -1 = anomalie
    df["ai_prediction"] = model.predict(df[features])

    df["ai_label"] = df["ai_prediction"].map(
        {
            1: "normal",
            -1: "anomaly",
        }
    )

    # Plus decision_function est faible, plus le log est suspect.
    # On inverse donc le score pour que plus grand = plus suspect.
    df["ai_raw_score"] = -model.decision_function(df[features])

    # Conversion en score lisible entre 0 et 100.
    min_score = df["ai_raw_score"].min()
    max_score = df["ai_raw_score"].max()

    if max_score > min_score:
        df["ai_score"] = (
            100
            * (df["ai_raw_score"] - min_score)
            / (max_score - min_score)
        ).round(1)
    else:
        df["ai_score"] = 0.0

    return df
