import os
import pandas as pd
import numpy as np
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import cross_val_score
from scipy.stats import spearmanr
import joblib

# Garantir que os diretórios necessários existam
os.makedirs("data", exist_ok=True)
os.makedirs("models", exist_ok=True)

# Carregar os dados pré-processados
X_train = pd.read_csv("data/X_train_preprocessed.csv")
X_test = pd.read_csv("data/X_test_preprocessed.csv")

# Separar features e labels
y_train = X_train["label"]
X_train = X_train.drop(columns=["label", "type"])

y_test = X_test["label"]
X_test = X_test.drop(columns=["label", "type"])

# ---- Método 1: Spearman Rank Correlation ---- #
def spearman_feature_selection(X, threshold=0.9):
    """
    Seleção de features usando Spearman Rank Correlation.
    Remove uma das features altamente correlacionadas com base no threshold.
    """
    corr_matrix = X.corr(method='spearman').abs()  # Matriz de correlação Spearman
    upper_triangle = np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)  # Triângulo superior da matriz
    to_drop = [
        column for column in corr_matrix.columns 
        if any(corr_matrix[column][upper_triangle[:, corr_matrix.columns.get_loc(column)]] > threshold)
    ]
    return X.drop(columns=to_drop), to_drop

# Aplicar seleção por Spearman
X_train_spearman, dropped_features_spearman = spearman_feature_selection(X_train)
print(f"Features removidas por Spearman: {dropped_features_spearman}")

# ---- Método 2: Chi-Squared Statistic ---- #
chi2_selector = SelectKBest(chi2, k=22)  # Selecionar as 22 melhores features
X_train_chi2 = chi2_selector.fit_transform(X_train, y_train)
selected_features_chi2 = X_train.columns[chi2_selector.get_support()].tolist()
print(f"Features selecionadas por Chi-Squared: {selected_features_chi2}")

# ---- Avaliação com Decision Tree ---- #
# Função para avaliar um conjunto de features usando Decision Tree e cross-validation
def evaluate_features(X, y):
    clf = DecisionTreeClassifier(random_state=42)
    scores = cross_val_score(clf, X, y, cv=5, scoring='accuracy')
    return scores.mean()

# Avaliar Spearman
spearman_score = evaluate_features(X_train_spearman, y_train)
print(f"Acurácia média com Spearman: {spearman_score}")

# Avaliar Chi-Squared
X_train_chi2_df = pd.DataFrame(X_train_chi2, columns=selected_features_chi2)
chi2_score = evaluate_features(X_train_chi2_df, y_train)
print(f"Acurácia média com Chi-Squared: {chi2_score}")

# Selecionar o melhor método
if spearman_score >= chi2_score:
    print("Spearman Rank Correlation selecionado como melhor método.")
    X_train_selected = X_train_spearman
    selected_features = X_train_spearman.columns.tolist()
else:
    print("Chi-Squared Statistic selecionado como melhor método.")
    X_train_selected = X_train_chi2_df
    selected_features = selected_features_chi2

# Aplicar o mesmo subconjunto de features no conjunto de teste
X_test_selected = X_test[selected_features]

# Salvar os datasets reduzidos e as features selecionadas
X_train_selected["label"] = y_train.values
X_test_selected["label"] = y_test.values

X_train_selected.to_csv("data/X_train_selected.csv", index=False)
X_test_selected.to_csv("data/X_test_selected.csv", index=False)

with open("models/selected_features.txt", "w") as f:
    f.write("\n".join(selected_features))

print("\nSeleção de features concluída!")
print(f"Conjunto final de features: {selected_features}")
