import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
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

# Lista de algoritmos para treinar
binary_models = {
    "RandomForest": RandomForestClassifier(random_state=42, n_estimators=100),
    "GradientBoosting": GradientBoostingClassifier(random_state=42),
    "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
    "KNeighbors": KNeighborsClassifier(n_neighbors=5)
}

multi_models = {
    "RandomForest": RandomForestClassifier(random_state=42, n_estimators=100),
    "GradientBoosting": GradientBoostingClassifier(random_state=42),
    "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
    "KNeighbors": KNeighborsClassifier(n_neighbors=5)
}

# Treinamento e salvamento para o modelo binário
print("Treinando modelos binários (label: benigno/maligno)...")
for name, model in binary_models.items():
    print(f"\nTreinando o modelo binário: {name}...")
    model.fit(X_train_bin, y_label_train)
    model_path = f"models/binary_model_{name}.pkl"
    joblib.dump(model, model_path)
    print(f"Modelo binário {name} salvo em '{model_path}'.")

# Treinamento e salvamento para o modelo multiclasse
print("\nTreinando modelos multiclasse (type: tipo de ataque)...")
for name, model in multi_models.items():
    print(f"\nTreinando o modelo multiclasse: {name}...")
    model.fit(X_train_multi, y_type_train)
    model_path = f"models/multi_model_{name}.pkl"
    joblib.dump(model, model_path)
    print(f"Modelo multiclasse {name} salvo em '{model_path}'.")

print("\nTreinamento concluído! Todos os modelos foram salvos na pasta 'models/'.")
