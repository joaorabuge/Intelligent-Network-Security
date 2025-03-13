import os
import psutil
import subprocess
import time
import numpy as np
import pandas as pd
import joblib
import signal
import warnings
warnings.filterwarnings("ignore")

# Diretório para armazenar os logs gerados pelo Zeek
LOG_DIR = "real-time/zeek_logs"
RAW_CSV = "real-time/raw_captured_data.csv"
FINAL_CSV = "real-time/final_captured_data.csv"

# Mapeamento das colunas dos logs para o DataFrame final
FIELD_MAPPINGS = {
    "conn.log": {
        "ts": "ts", "id.orig_h": "src_ip", "id.orig_p": "src_port",
        "id.resp_h": "dst_ip", "id.resp_p": "dst_port", "proto": "proto",
        "service": "service", "duration": "duration", "orig_bytes": "src_bytes",
        "resp_bytes": "dst_bytes", "conn_state": "conn_state", "missed_bytes": "missed_bytes",
        "orig_pkts": "src_pkts", "orig_ip_bytes": "src_ip_bytes", "resp_pkts": "dst_pkts",
        "resp_ip_bytes": "dst_ip_bytes"
    },
    "dns.log": {
        "ts": "ts", "id.orig_h": "src_ip", "id.orig_p": "src_port",
        "id.resp_h": "dst_ip", "id.resp_p": "dst_port", "proto": "proto",
        "query": "dns_query", "qclass": "dns_qclass", "qtype": "dns_qtype",
        "rcode": "dns_rcode", "AA": "dns_AA", "RD": "dns_RD", "RA": "dns_RA", "rejected": "dns_rejected"
    },
    "ssl.log": {
        "ts": "ts", "id.orig_h": "src_ip", "id.orig_p": "src_port", "id.resp_h": "dst_ip", "id.resp_p": "dst_port",
        "version": "ssl_version", "cipher": "ssl_cipher", "resumed": "ssl_resumed",
        "established": "ssl_established", "server_name": "ssl_subject", "issuer": "ssl_issuer"
    },
    "http.log": {
        "ts": "ts", "id.orig_h": "src_ip", "id.orig_p": "src_port", "id.resp_h": "dst_ip", "id.resp_p": "dst_port",
        "trans_depth": "http_trans_depth", "method": "http_method", "uri": "http_uri",
        "referrer": "http_referrer", "version": "http_version", "request_body_len": "http_request_body_len",
        "response_body_len": "http_response_body_len", "status_code": "http_status_code",
        "user_agent": "http_user_agent", "orig_mime_types": "http_orig_mime_types", "resp_mime_types": "http_resp_mime_types"
    },
    "weird.log": {
        "ts": "ts", "id.orig_h": "src_ip", "id.orig_p": "src_port", 
        "id.resp_h": "dst_ip", "id.resp_p": "dst_port", 
        "name": "weird_name", "addl": "weird_addl", "notice": "weird_notice"
    }
}


# Carregar modelos e pré-processador
binary_model = joblib.load("models/binary_model_RandomForest.pkl")
multi_model = joblib.load("models/multi_model_RandomForest.pkl")
preprocessor = joblib.load("models/preprocessor.pkl")

NUMERIC_COLUMNS = [
    "ts", "src_port", "dst_port", "duration", "src_bytes", "dst_bytes",
    "missed_bytes", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes",
    "dns_qclass", "dns_qtype", "dns_rcode", "http_request_body_len",
    "http_response_body_len", "http_status_code"
]


def get_active_interfaces():
    """
    Retorna uma lista de interfaces de rede ativas com tráfego.
    """
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    return [iface for iface, stat in stats.items() if stat.isup and iface in interfaces]

def get_active_interfaces():
    """
    Retorna uma lista de interfaces de rede ativas com tráfego.
    """
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    active_interfaces = [
        iface for iface, stat in stats.items()
        if stat.isup and iface in interfaces
    ]
    return active_interfaces


def clean_previous_files():
    """
    Remove arquivos antigos no diretório de logs e os arquivos CSV gerados anteriormente.
    Além disso, encerra quaisquer processos Zeek ativos.
    """
    if os.path.exists(LOG_DIR):
        for file in os.listdir(LOG_DIR):
            file_path = os.path.join(LOG_DIR, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f"Arquivo removido: {file_path}")
    else:
        os.makedirs(LOG_DIR)
        print(f"Diretório criado: {LOG_DIR}")

    for csv_file in [RAW_CSV, FINAL_CSV]:
        if os.path.exists(csv_file):
            os.remove(csv_file)
            print(f"Arquivo removido: {csv_file}")

    # Encerrar processos Zeek ativos
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if 'zeek' in proc.info['name']:
                print(f"Encerrando processo Zeek: {proc.info['pid']}")
                proc.terminate()  # Tente encerrar o processo graciosamente
                proc.wait(timeout=3)
    except Exception as e:
        print(f"Erro ao encerrar processos Zeek: {e}")

        
def start_zeek_capture(interface="en0", script_name="real-time/force_all_logs.zeek", duration=60, password=None, pcap_file=None):
    """
    Inicia a captura com Zeek ou processa um arquivo PCAP.
    """
    os.makedirs(LOG_DIR, exist_ok=True)  # Certifique-se de que o diretório `LOG_DIR` existe

    process = None  # Inicialize o processo como None para rastrear o processo principal

    if pcap_file:
        print(f"Processando arquivo PCAP: {pcap_file}")
        try:
            subprocess.run(["zeek", "-r", pcap_file, script_name], check=True)
            print("Processamento de PCAP concluído.")
        except subprocess.CalledProcessError as e:
            print(f"Erro ao processar o arquivo PCAP: {e}")
            exit(1)
    else:
        print(f"Iniciando captura com Zeek na interface {interface} por {duration} segundos...")
        try:
            if password:
                command = f"echo {password} | sudo -S zeek -i {interface} {script_name}"
                process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
            else:
                process = subprocess.Popen(["sudo", "zeek", "-i", interface, script_name], preexec_fn=os.setsid)
            
            time.sleep(duration)

            # Encerra o processo principal e seus subprocessos
            if process:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)  # Encerra o grupo de processos
                print("Captura encerrada.")
        except subprocess.CalledProcessError as e:
            print(f"Erro ao executar o Zeek: {e}")
            exit(1)

    # Adicionar um pequeno atraso para garantir que todos os arquivos sejam gerados
    time.sleep(2)

    # Mover logs gerados para o diretório 'zeek_logs'
    for item in os.listdir("."):
        item_path = os.path.join(".", item)
        if os.path.isfile(item_path) and item.endswith(".log"):
            destination = os.path.join(LOG_DIR, item)
            try:
                os.rename(item_path, destination)
                print(f"Log movido para {LOG_DIR}: {item}")
            except Exception as e:
                print(f"Erro ao mover o log {item}: {e}")

    print("Todos os logs foram movidos para o diretório 'zeek_logs'.")




def process_zeek_logs():
    """
    Processa os logs gerados pelo Zeek no diretório 'real-time/zeek_logs' em um DataFrame consolidado.
    """
    rows = []
    for log_file in os.listdir(LOG_DIR):
        log_path = os.path.join(LOG_DIR, log_file)
        if log_file in FIELD_MAPPINGS and os.path.exists(log_path):
            print(f"Processando log: {log_file}")
            with open(log_path, "r") as file:
                headers = []
                for line in file:
                    if line.startswith("#fields"):
                        headers = line.strip().split("\t")[1:]
                    elif not line.startswith("#"):
                        fields = line.strip().split("\t")
                        # Inicializar o dicionário com valores padrão
                        row = {feature: ("0" if feature in NUMERIC_COLUMNS else "-") 
                               for feature in FIELD_MAPPINGS[log_file].values()}
                        for zeek_field, csv_field in FIELD_MAPPINGS[log_file].items():
                            if zeek_field in headers:
                                value = fields[headers.index(zeek_field)]
                                row[csv_field] = value if value.strip() else ("0" if csv_field in NUMERIC_COLUMNS else "-")
                        rows.append(row)

    if not rows:
        print("Nenhum dado foi extraído dos logs do Zeek.")
        return pd.DataFrame()

    data = pd.DataFrame(rows)

    # Garantir que as colunas numéricas sejam representadas como strings de "0"
    for col in NUMERIC_COLUMNS:
        if col in data.columns:
            data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0).astype(int).astype(str)

    # Preencher valores ausentes nas colunas categóricas com "-"
    for col in data.columns:
        if col not in NUMERIC_COLUMNS:
            data[col] = data[col].fillna("-").astype(str)

    # Garantir a ordem especificada para salvar o CSV
    final_columns_order = [
        "ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service",
        "duration", "src_bytes", "dst_bytes", "conn_state", "missed_bytes",
        "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes", "dns_query",
        "dns_qclass", "dns_qtype", "dns_rcode", "dns_AA", "dns_RD", "dns_RA",
        "dns_rejected", "ssl_version", "ssl_cipher", "ssl_resumed", "ssl_established",
        "ssl_subject", "ssl_issuer", "http_trans_depth", "http_method", "http_uri",
        "http_referrer", "http_version", "http_request_body_len", "http_response_body_len",
        "http_status_code", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
        "weird_name", "weird_addl", "weird_notice", "label", "type"
    ]

    # Garantir que todas as colunas da ordem final estejam no DataFrame
    for col in final_columns_order:
        if col not in data.columns:
            if col in NUMERIC_COLUMNS:
                data[col] = "0"  # Valores numéricos padrão como string "0"
            else:
                data[col] = "-"  # Valores categóricos padrão como "-"

    # Reordenar as colunas
    data = data[final_columns_order]

    # Salvar os dados capturados antes do pré-processamento
    raw_csv_path = RAW_CSV
    data.to_csv(raw_csv_path, index=False)
    print(f"Dados capturados salvos em: {raw_csv_path}")

    return data

def classify_traffic(data):
    """
    Classifica tráfego em tempo real com consulta ao ChatGPT para tráfego anômalo.
    """
    if data.empty:
        print("Nenhum dado para classificar.")
        return []
    
    predicted_data = pd.DataFrame()  # Inicialização de segurança

    # Adicionar colunas ausentes com valores padrão
    expected_columns = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service",
                        "duration", "src_bytes", "dst_bytes", "conn_state", "missed_bytes",
                        "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes", "dns_query",
                        "dns_qclass", "dns_qtype", "dns_rcode", "dns_AA", "dns_RD", "dns_RA",
                        "dns_rejected", "ssl_version", "ssl_cipher", "ssl_resumed", "ssl_established",
                        "ssl_subject", "ssl_issuer", "http_trans_depth", "http_method", "http_uri",
                        "http_referrer", "http_version", "http_user_agent", "http_orig_mime_types",
                        "http_resp_mime_types", "http_request_body_len", "http_response_body_len",
                        "http_status_code"]

    for col in expected_columns:
        if col not in data.columns:
            if (col.startswith("http") and col not in ["http_trans_depth", "http_user_agent"]) or col in ["duration", "src_bytes", "dst_bytes"]:
                data[col] = 0
            else:
                data[col] = "-"


    # Identificar colunas categóricas e numéricas
    categorical_cols = data.select_dtypes(include=["object"]).columns.tolist()
    numerical_cols = data.select_dtypes(include=["number"]).columns.tolist()

    # Corrigir valores problemáticos nas colunas específicas
    for col in ["src_port", "dst_port"]:
        data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0).astype(int)

    for col in ["dst_bytes", "missed_bytes", "src_pkts", "src_ip_bytes"]:
        data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0).astype(float)

    for col in ["dns_rcode"]:
        data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0).astype(float)

    # Garantir que `http_user_agent` e `http_trans_depth` sejam preenchidos corretamente
    for col in ["http_user_agent", "http_trans_depth"]:
        if col in data.columns:
            data[col] = data[col].apply(lambda x: "-" if pd.isna(x) else x).astype(str)
        else:
            data[col] = "-"

    # Converter colunas categóricas para valores numéricos
    for col in categorical_cols:
        if col in preprocessor["label_encoders"]:
            unseen_value = "-"
            data[col] = data[col].apply(lambda x: x if x in preprocessor["label_encoders"][col].classes_ else unseen_value)
            if unseen_value not in preprocessor["label_encoders"][col].classes_:
                preprocessor["label_encoders"][col].classes_ = np.append(preprocessor["label_encoders"][col].classes_, unseen_value)
            data[col] = preprocessor["label_encoders"][col].transform(data[col])
        else:
            data[col] = data[col].fillna("-").astype(str)

    # Converter colunas numéricas para float e substituir valores inválidos
    for col in numerical_cols:
        data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0)

    # Diagnóstico: verificar colunas e tipos antes do scaler
    print("Data antes de aplicar o scaler:")
    print(data.info())
    print(data.head())

    # Verificar as features esperadas pelo scaler
    scaler = preprocessor["scaler"]
    print("Feature names esperadas pelo scaler:")
    print(scaler.feature_names_in_)

    # Debug: Comparar colunas esperadas pelo scaler e as colunas atuais do DataFrame
    expected_features = set(scaler.feature_names_in_)
    actual_features = set(data.columns)
    missing_features = expected_features - actual_features
    extra_features = actual_features - expected_features
    print("Features esperadas pelo scaler:", scaler.feature_names_in_)
    print("Features atuais no DataFrame:", list(data.columns))
    print("Features faltantes:", missing_features)
    print("Features extras:", extra_features)

    # Garantir que as colunas correspondem às do scaler
    for col in scaler.feature_names_in_:
        if col not in data.columns:
            print(f"Coluna '{col}' ausente no DataFrame. Adicionando com valor padrão 0.")
            data[col] = 0
        elif not pd.api.types.is_numeric_dtype(data[col]):
            print(f"Coluna '{col}' contém valores não numéricos:")
            print(data[col].unique())

    # Reordenar as colunas para corresponder ao scaler
    data = data[scaler.feature_names_in_]

    preprocessed_csv_path = "real-time/preprocessed_capture_data.csv"
    predicted_data.to_csv(preprocessed_csv_path, index=False)
    print(f"Dados finais com previsões salvos em: {preprocessed_csv_path}")

    # Aplicar o scaler
    X_preprocessed = scaler.transform(data)

    # Classificar tráfego
    label_pred = binary_model.predict(X_preprocessed)
    results = []
    predicted_data = data.copy()

    for idx, probabilities in enumerate(binary_model.predict_proba(X_preprocessed)):
        benign_confidence = probabilities[0]  # Confiança para "benigno"
        malign_confidence = probabilities[1]  # Confiança para "maligno"

        if benign_confidence > malign_confidence:  # Benigno com alta confiança
            results.append({
                "label": "benigno", 
                "type": "normal", 
                "confidence": benign_confidence
            })
            predicted_data.at[idx, "label"] = 0
            predicted_data.at[idx, "type"] = "normal"
            predicted_data.at[idx, "confidence"] = benign_confidence
            
        elif malign_confidence < 0.8:  # Benigno com baixa confiança
            results.append({
                "label": "benigno", 
                "type": "normal", 
                "confidence": benign_confidence
            })
            predicted_data.at[idx, "label"] = 0
            predicted_data.at[idx, "type"] = "normal"
            predicted_data.at[idx, "confidence"] = benign_confidence

        else:  # Maligno com alta confiança
            type_pred_proba = multi_model.predict_proba([X_preprocessed[idx]])[0]
            type_pred = multi_model.classes_[type_pred_proba.argmax()]
            attack_confidence = type_pred_proba.max()

            if malign_confidence < 0.85:  # Limite de confiança para maligno
                results.append({
                    "label": "maligno", 
                    "type": "Tráfego anómalo", 
                    "confidence": malign_confidence
                })
                predicted_data.at[idx, "label"] = 1
                predicted_data.at[idx, "type"] = "Tráfego anómalo"
                predicted_data.at[idx, "confidence"] = malign_confidence
            else:
                results.append({
                    "label": "maligno", 
                    "type": type_pred, 
                    "confidence": attack_confidence
                })
                predicted_data.at[idx, "label"] = 1
                predicted_data.at[idx, "type"] = type_pred
                predicted_data.at[idx, "confidence"] = attack_confidence

    # Salvar os resultados
    final_csv_path = "real-time/final_captured_data.csv"
    predicted_data.to_csv(final_csv_path, index=False)
    print(f"Dados finais com previsões salvos em: {final_csv_path}")

    # Retornar resultados e dados para o gráfico
    graph_data = generate_graph_data(predicted_data)
    return results, graph_data



def generate_graph_data(data):
    """
    Processa os dados e retorna a distribuição de pacotes benignos e malignos
    e os tipos de ataques para uso na interface.
    """
    benign_count = data[data["label"] == 0].shape[0]
    malign_count = data[data["label"] == 1].shape[0]

    attack_types = (
        data[data["label"] == 1]["type"].value_counts().to_dict()
        if malign_count > 0
        else {}
    )

    return {
        "benign_count": benign_count,
        "malign_count": malign_count,
        "attack_types": attack_types,
    }


def main():
    clean_previous_files()

    interface = input("Insira a interface de rede (ex: en0): ")
    duration = int(input("Insira a duração da captura (segundos): "))
    start_zeek_capture(interface=interface, duration=duration)
    data = process_zeek_logs()
    results = classify_traffic(data)

if __name__ == "__main__":
    main()
