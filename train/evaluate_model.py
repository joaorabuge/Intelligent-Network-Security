import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
import json

# Criar diretório para salvar os resultados, se não existir
os.makedirs("results", exist_ok=True)

# Carregar os dados de teste pré-processados
X_test = pd.read_csv("data/X_test_preprocessed.csv")

# Separar labels e features para o modelo binário
y_label_test = X_test["label"]
X_test_bin = X_test.drop(columns=["label", "type"])

# Separar dados para o modelo multiclasse (apenas casos malignos)
X_test_multi = X_test[X_test["label"] == 1].drop(columns=["label", "type"])
y_type_test = X_test[X_test["label"] == 1]["type"]

# Inicializar dicionário para resultados
results = {}

# Avaliação do modelo binário RandomForest
print("Avaliando modelo binário (label: benigno/maligno) RandomForest...")
results["binary_models"] = {}
model_name = "RandomForest"
model_path = f"models/binary_model_{model_name}.pkl"
model = joblib.load(model_path)

y_label_pred = model.predict(X_test_bin)
conf_matrix = confusion_matrix(y_label_test, y_label_pred)
class_report = classification_report(y_label_test, y_label_pred, output_dict=True)

if hasattr(model, "feature_importances_"):
    feature_importance = {
        "features": X_test_bin.columns.tolist(),
        "importance": model.feature_importances_.tolist(),
    }
else:
    feature_importance = None

results["binary_models"][model_name] = {
    "confusion_matrix": conf_matrix.tolist(),
    "classification_report": class_report,
    "feature_importance": feature_importance,
}

# Avaliação do modelo multiclasse RandomForest
print("\nAvaliando modelo multiclasse (type: tipo de ataque) RandomForest...")
results["multi_models"] = {}
model_path = f"models/multi_model_{model_name}.pkl"
model = joblib.load(model_path)

y_type_pred = model.predict(X_test_multi)
conf_matrix = confusion_matrix(y_type_test, y_type_pred)
class_report = classification_report(y_type_test, y_type_pred, output_dict=True)

if hasattr(model, "feature_importances_"):
    feature_importance = {
        "features": X_test_multi.columns.tolist(),
        "importance": model.feature_importances_.tolist(),
    }
else:
    feature_importance = None

results["multi_models"][model_name] = {
    "confusion_matrix": conf_matrix.tolist(),
    "classification_report": class_report,
    "feature_importance": feature_importance,
}

# Salvar os resultados em formato JSON
with open("results/model_evaluation.json", "w") as f:
    json.dump(results, f)

print("\nResultados da avaliação salvos em 'results/model_evaluation.json'")
