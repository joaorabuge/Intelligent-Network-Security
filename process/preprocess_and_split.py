import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from scipy.stats import spearmanr
import joblib

# Garantir que os diretórios necessários existam
os.makedirs("data", exist_ok=True)
os.makedirs("models", exist_ok=True)

# Carregar o dataset combinado
file_path = "combined_csvs/combined_dataset.csv"  # Substitua pelo caminho correto
data = pd.read_csv(file_path, low_memory=False)

# Remover colunas irrelevantes
data = data.drop(columns=["src_ip", "dst_ip"])

# Tratar atributos que devem ser preenchidos com "-"
data['http_trans_depth'] = data['http_trans_depth'].fillna("-").astype(str)
data['http_user_agent'] = data['http_user_agent'].fillna("-").astype(str)

# Separar features (X) e alvos (y)
X = data.drop(columns=["label", "type"])
y_label = data["label"]  # Binário: benigno (0) ou maligno (1)
y_type = data["type"]    # Multiclasse: tipos de ataque

# Identificar colunas categóricas e numéricas
categorical_cols = X.select_dtypes(include=["object"]).columns
numerical_cols = X.select_dtypes(include=["number"]).columns

# Codificar atributos categóricos
label_encoders = {}
for col in categorical_cols:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col].astype(str))
    label_encoders[col] = le

# Remover colunas constantes
X = X.loc[:, (X != X.iloc[0]).any()]

# Seleção de Features usando correlação de Spearman
correlation_matrix = X.corr(method=lambda x, y: spearmanr(x, y)[0])
columns_to_drop = []
threshold = 0.9
for col in correlation_matrix.columns:
    for index in correlation_matrix.index:
        if index != col and abs(correlation_matrix.loc[index, col]) > threshold:
            if index not in columns_to_drop:
                columns_to_drop.append(index)

X = X.drop(columns=columns_to_drop)

# Normalização dos dados
scaler = MinMaxScaler()
X_normalized = scaler.fit_transform(X)

# Dividir o dataset em treino e teste
X_train, X_test, y_label_train, y_label_test, y_type_train, y_type_test = train_test_split(
    X_normalized, y_label, y_type, test_size=0.2, random_state=42
)

# Converter para DataFrame e adicionar labels
X_train_df = pd.DataFrame(X_train, columns=X.columns)
X_test_df = pd.DataFrame(X_test, columns=X.columns)

X_train_df["label"] = y_label_train.values
X_train_df["type"] = y_type_train.values

X_test_df["label"] = y_label_test.values
X_test_df["type"] = y_type_test.values

# Salvar conjuntos pré-processados como CSV
X_train_df.to_csv("data/X_train_preprocessed.csv", index=False)
X_test_df.to_csv("data/X_test_preprocessed.csv", index=False)

# Consolidar scaler e label_encoders em um único objeto
preprocessor = {
    "scaler": scaler,
    "label_encoders": label_encoders
}

# Salvar o objeto consolidado
joblib.dump(preprocessor, "models/preprocessor.pkl")
print("\nPré-processamento concluído! Arquivos salvos em 'data/' e 'models/'.")
