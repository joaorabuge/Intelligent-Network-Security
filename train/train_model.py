import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Criar diretório para salvar os modelos, se não existir
os.makedirs("models", exist_ok=True)

# Carregar os dados pré-processados
X_train = pd.read_csv("data/X_train_preprocessed.csv")

# Separar labels e features para o modelo binário
y_label_train = X_train["label"]
X_train_bin = X_train.drop(columns=["label", "type"])  # Remove também o campo 'type' para o binário

# Separar dados para o modelo multiclasse (apenas casos malignos)
X_train_multi = X_train[X_train["label"] == 1].drop(columns=["label", "type"])
y_type_train = X_train[X_train["label"] == 1]["type"]

# Treinamento para o modelo binário usando RandomForest
print("Treinando modelo binário (label: benigno/maligno) com RandomForest...")
rf_binary = RandomForestClassifier(random_state=42, n_estimators=100)
rf_binary.fit(X_train_bin, y_label_train)
model_path_bin = "models/binary_model_RandomForest.pkl"
joblib.dump(rf_binary, model_path_bin)
print(f"Modelo binário RandomForest salvo em '{model_path_bin}'.")

# Treinamento para o modelo multiclasse usando RandomForest
print("\nTreinando modelo multiclasse (type: tipo de ataque) com RandomForest...")
rf_multi = RandomForestClassifier(random_state=42, n_estimators=100)
rf_multi.fit(X_train_multi, y_type_train)
model_path_multi = "models/multi_model_RandomForest.pkl"
joblib.dump(rf_multi, model_path_multi)
print(f"Modelo multiclasse RandomForest salvo em '{model_path_multi}'.")

print("\nTreinamento concluído! Os modelos foram salvos na pasta 'models/'.")
