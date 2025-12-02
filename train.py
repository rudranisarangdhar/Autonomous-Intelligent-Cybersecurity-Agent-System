import numpy as np
from utils import generate_advanced_flow, evaluate_model, save_model
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier


def train_and_save_model():
    print("🔄 Generating advanced dataset...")
    df = generate_advanced_flow(7000)

    df = df.sample(frac=1).reset_index(drop=True)

    FEATURES = [
        "duration", "src_bytes", "dst_bytes", "flag",
        "failed_logins", "hot", "same_srv_rate", "packets"
    ]

    X = df[FEATURES]
    y = df["label"]

    print("🔄 Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42
    )

    print("🔄 Training RandomForest model...")
    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=8,     # reduced depth → prevents memorizing → realistic
        random_state=42
    )
    model.fit(X_train, y_train)

    print("🔍 Evaluating...")
    acc = evaluate_model(model, X_test, y_test)

    save_model(model)
    print("\n🎉 Training complete. Final Accuracy:", round(acc, 4))

    return acc


if __name__ == "__main__":
    train_and_save_model()
