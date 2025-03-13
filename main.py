import os
import time
import sys
sys.path.append("real-time")
import subprocess
import hashlib
import pexpect
import json
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, bcrypt, login_manager, User, PCAPResult, RealtimeResult
from config import Config
from real_time_streaming import clean_previous_files, start_zeek_capture, process_zeek_logs, classify_traffic
from real_time_streaming import get_active_interfaces
from flask import render_template, request, jsonify
from flask_login import login_required
from chatbot import generate_chatbot_response
import pandas as pd
import json
import numpy as np
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import jsonify
from datetime import datetime
import pytz



# Caminhos principais
COMBINE_CSVS="combined_csvs"
DATASET_DIR = "dataset"
COMBINED_DATASET_PATH = os.path.join(COMBINE_CSVS, "combined_dataset.csv")
HASH_FILE = os.path.join(DATASET_DIR, "dataset_hash.txt")
PREPROCESS_SCRIPT = "process/preprocess_and_split.py"
TRAIN_SCRIPT = "train/train_model.py"
EVALUATE_SCRIPT = "train/evaluate_model.py"
REALTIME_SCRIPT = "real-time/real_time_streaming.py"
PCAP_SCRIPT = "real-time/pcap_streaming.py"

# Configurar Flask
app = Flask(__name__)
app.config.from_object(Config)
app.jinja_env.globals.update(zip=zip)
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)

login_manager.login_view = "login"
login_manager.login_message_category = "info"

def get_lisbon_time():
    utc_time = datetime.now(pytz.utc)  # Get current UTC time
    lisbon_tz = pytz.timezone("Europe/Lisbon")
    local_time = utc_time.astimezone(lisbon_tz)
    return local_time.strftime("%H:%M")


def calculate_dataset_hash():
    """
    Calcula o hash do conteúdo de todos os arquivos CSV no diretório `dataset/`,
    ignorando o diretório `combined_csvs`.
    """
    hash_md5 = hashlib.md5()
    csv_files = sorted(
        [os.path.join(DATASET_DIR, f) for f in os.listdir(DATASET_DIR) if f.endswith(".csv")]
    )
    for csv_file in csv_files:
        with open(csv_file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    return hash_md5.hexdigest()


def load_previous_hash():
    """
    Carrega o hash armazenado anteriormente, se existir.
    """
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as file:
            return file.read().strip()
    return None

def save_current_hash(hash_value):
    """
    Salva o hash atual no arquivo de hash.
    """
    with open(HASH_FILE, "w") as file:
        file.write(hash_value)

PIPELINE_STATE_FILE = "dataset/pipeline_state.txt"

def load_pipeline_state():
    """Carrega o estado atual do pipeline."""
    if os.path.exists(PIPELINE_STATE_FILE):
        with open(PIPELINE_STATE_FILE, "r") as file:
            return file.read().strip()
    return "completed"  # Default: completed

def save_pipeline_state(state):
    """Salva o estado atual do pipeline."""
    with open(PIPELINE_STATE_FILE, "w") as file:
        file.write(state)

def check_for_updates():
    """Verifica se há novos dados e define o estado do pipeline."""
    print("\n--- Verificando atualizações no dataset ---")
    current_hash = calculate_dataset_hash()
    previous_hash = load_previous_hash()
    pipeline_state = load_pipeline_state()
    print(f"DEBUG: Hash atual: {current_hash}, Hash anterior: {previous_hash}, Estado do pipeline: {pipeline_state}")

    if current_hash != previous_hash:
        print("Novos dados detectados!")
        save_current_hash(current_hash)
        save_pipeline_state("pending")  # Define como pendente
        return True
    elif pipeline_state == "pending":
        print("Pipeline pendente de execução.")
        return True
    else:
        print("Nenhuma atualização detectada.")
        return False



def update_pipeline():
    """
    Executa as etapas de combinação, pré-processamento e treinamento.
    Retorna True se todas as etapas forem bem-sucedidas.
    """
    os.makedirs(COMBINE_CSVS, exist_ok=True)

    try:
        print("DEBUG: Executando combine_csvs.py...")
        subprocess.run(["python", "dataset/combine_csvs.py"], check=True)
        print("DEBUG: combine_csvs.py concluído.")

        # Verificar se o arquivo combinado foi salvo no diretório correto
        combined_file_path = os.path.join(COMBINE_CSVS, "combined_dataset.csv")
        if os.path.exists(combined_file_path):
            print(f"DEBUG: Arquivo combinado salvo em {combined_file_path}")
        else:
            print("ERRO: O arquivo combinado não foi encontrado após a execução.")


        print("DEBUG: Executando preprocess_and_split.py...")
        subprocess.run(["python", PREPROCESS_SCRIPT], check=True)
        print("DEBUG: preprocess_and_split.py concluído.")

        print("DEBUG: Executando train_model.py...")
        subprocess.run(["python", TRAIN_SCRIPT], check=True)
        print("DEBUG: train_model.py concluído.")

        return True
    except subprocess.CalledProcessError as e:
        print(f"ERRO: Falha ao executar o pipeline: {e}")
        return False




def generate_graph_data_1(data):
    """
    Processa os dados e retorna a distribuição de pacotes benignos e malignos
    e os tipos de ataques para uso na interface.
    """
    # Garantir que a coluna 'label' exista e esteja em formato esperado
    if "label" not in data.columns:
        print("DEBUG: Coluna 'label' ausente nos dados fornecidos.")
        return {
            "benign_count": 0,
            "malign_count": 0,
            "attack_types": {}
        }
    
    # Garantir que os valores de 'label' sejam strings e normalizados
    data["label"] = data["label"].astype(str).str.lower()

    # Contar pacotes benignos e malignos
    benign_count = data[data["label"] == "benign"].shape[0]
    malign_count = data[data["label"] == "malign"].shape[0]

    print(f"DEBUG: Contagem de benignos: {benign_count}, malignos: {malign_count}")

    # Contar tipos de ataques, apenas para pacotes malignos
    if "type" in data.columns and malign_count > 0:
        attack_types = data[data["label"] == "malign"]["type"].value_counts().to_dict()
    else:
        print("DEBUG: Coluna 'type' ausente ou nenhum pacote maligno encontrado.")
        attack_types = {}

    print(f"DEBUG: Tipos de ataques identificados: {attack_types}")

    return {
        "benign_count": benign_count,
        "malign_count": malign_count,
        "attack_types": attack_types,
    }

def combine_raw_and_final(
    raw_csv="real-time/raw_captured_data.csv", 
    final_csv="real-time/final_captured_data.csv", 
    output_csv="real-time/combined_data.csv"
):
    """
    Combines the raw captured data (with detailed fields such as IP addresses) 
    and the final processed data (which contains label, type, and confidence) 
    into a single CSV file.
    
    Since the row order is guaranteed to be the same, we simply concatenate the
    additional columns from the final CSV to the raw CSV.
    """
    df_raw = pd.read_csv(raw_csv)
    df_final = pd.read_csv(final_csv)
    
    # Check if both files have the same number of rows.
    if df_raw.shape[0] != df_final.shape[0]:
        raise ValueError("The raw and final CSV files do not have the same number of rows.")
    
    df_combined = df_raw.copy()
    for col in ["type", "label"]:
        if col in df_final.columns:
            df_combined[col] = df_final[col]
        else:
            print(f"Warning: Column '{col}' not found in the final CSV.")
    
    df_combined.to_csv(output_csv, index=False)
    return output_csv

import pandas as pd

import pandas as pd

def get_network_context_from_combined(csv_path="real-time/combined_data.csv"):
    """
    Reads the combined CSV and returns a comprehensive summary of every parameter,
    designed to supply detailed context to the mitigation chatbot.
    
    The summary includes:
      - Overall traffic statistics:
          * Total packets.
          * Normal packets (assumed to be labeled as "normal").
          * Anomalous packets (any label not equal to "normal", using the attack name if provided).
          * Time range from the timestamp (ts).
          * Distribution of attack types (from the normalized label).
      - For each numeric column (e.g., duration, src_bytes, dst_bytes, src_pkts, dst_pkts):
          * Mean, min, max, and unique count.
      - For each categorical column (e.g., src_ip, dst_ip, proto, service, dns_qtype, ssl_version, http_method, etc.):
          * Top 10 most frequent values and the unique count.
      - Additional markers (e.g., weird_addl, weird_notice) if available.
    
    Returns a dictionary with the summary as a JSON-formatted string under the key "full_network_summary".
    """
    try:
        df = pd.read_csv(csv_path)
        
        # Normalize the label column: convert to string, strip whitespace, and map numeric labels.
        df["label"] = (
            df["label"]
            .astype(str)
            .str.strip()
            .replace({"0": "normal", "0.0": "normal", "1": "malign", "1.0": "malign"})
            .str.lower()
        )
        
        # Use the 'type' column for rows labeled as "malign"
        def normalize_label(row):
            lab = row["label"]
            if lab in ["malign"]:
                attack = str(row.get("type", "")).strip().lower()
                return attack if attack and attack != "nan" else "malign"
            else:
                return lab
        
        df["normalized_label"] = df.apply(normalize_label, axis=1)
        
        # Overall traffic statistics
        total_packets = df.shape[0]
        normal_count = df[df["normalized_label"] == "normal"].shape[0]
        anomalous_count = total_packets - normal_count
        # Time range from 'ts'
        ts_values = pd.to_numeric(df["ts"], errors="coerce")
        time_range = {"min": ts_values.min(), "max": ts_values.max()}
        attack_types = df[df["normalized_label"] != "normal"]["normalized_label"].value_counts().to_dict() if anomalous_count > 0 else {}
        
        overall_stats = {
            "total_packets": total_packets,
            "normal_packets": normal_count,
            "anomalous_packets": anomalous_count,
            "time_range": time_range,
            "attack_types": attack_types
        }
        
        # For numeric columns: gather descriptive statistics
        numeric_columns = [col for col in df.columns if pd.api.types.is_numeric_dtype(df[col])]
        numeric_stats = {}
        for col in numeric_columns:
            desc = df[col].describe()
            numeric_stats[col] = {
                "mean": round(desc.get("mean", 0), 2),
                "min": desc.get("min", 0),
                "max": desc.get("max", 0),
                "unique_count": int(df[col].nunique())
            }
        
        # For categorical columns: gather top 10 values and unique count.
        categorical_columns = [col for col in df.columns if df[col].dtype == "object" and col not in ["label", "type", "normalized_label"]]
        categorical_stats = {}
        for col in categorical_columns:
            freq = df[col].value_counts().head(10).to_dict()
            categorical_stats[col] = {
                "frequency_distribution": freq,
                "unique_count": int(df[col].nunique())
            }
        
        # Additional markers: e.g., weird fields if available.
        additional_markers = {}
        for marker in ["weird_addl", "weird_notice"]:
            if marker in df.columns:
                additional_markers[marker] = df[marker].value_counts().head(10).to_dict()
        
        full_summary = {
            "overall_stats": overall_stats,
            "numeric_stats": numeric_stats,
            "categorical_stats": categorical_stats,
            "additional_markers": additional_markers
        }
        
        summary_json = json.dumps(full_summary, indent=2, default=lambda o: int(o) if isinstance(o, np.int64) else o)
        return {"full_network_summary": summary_json}
    except Exception as e:
        return {"error": str(e)}







    
# ---- ROTAS FLASK ---- #
@app.route("/")
def home():
    return render_template("home.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Verificar se o username já existe
        if User.query.filter_by(username=username).first():
            flash("Username already used. Please choose another one and try again!", "danger")
            return redirect(url_for("register"))

        # Verificar se o email já existe
        if User.query.filter_by(email=email).first():
            flash("E-mail already associated with an account. Try again.", "danger")
            return redirect(url_for("register"))

        # Se o username e email forem únicos, adicionar o novo utilizador
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account successfuly created!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        # Try to find the user by email
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            # Successful login
            login_user(user)
            return redirect(url_for("home"))  # Redirect to home after login
        else:
            # If username or password is incorrect
            flash("Invalid username or password. Please try again.", "danger")
    
    return render_template("login.html")




@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))  # Redirect after logout



@app.route("/dashboard")
@login_required
def dashboard():
    pcap_results = PCAPResult.query.filter_by(user_id=current_user.id).all()
    realtime_results = RealtimeResult.query.filter_by(user_id=current_user.id).all()
    active_interfaces = get_active_interfaces()  # Obtém interfaces ativas

    # Verificar atualizações
    update_available = check_for_updates()

    return render_template(
        "dashboard.html",
        pcap_results=pcap_results,
        realtime_results=realtime_results,
        active_interfaces=active_interfaces,  # Passa interfaces para o template
        update_available=update_available  # Passa se há atualizações disponíveis
    )
@app.route("/real-time", methods=["GET"])
@login_required
def realtime_analysis():
    active_interfaces = get_active_interfaces()
    return render_template("realtime.html", active_interfaces=active_interfaces)


@app.route("/realtime", methods=["GET", "POST"])
@login_required
def realtime():
    active_interfaces = get_active_interfaces()

    if request.method == "POST":
        interface = request.form["interface"]
        duration = int(request.form["duration"])
        password = request.form.get("password", None)

        try:
            clean_previous_files()
            start_zeek_capture(interface=interface, duration=duration, password=password)
            data = process_zeek_logs()
            results, graph_data = classify_traffic(data)

            # Save results in the database
            result_text = json.dumps(results)
            new_result = RealtimeResult(result=result_text, user_id=current_user.id)
            db.session.add(new_result)
            db.session.commit()

            flash("Real-Time traffic analyzed successfully!", "success")
            return render_template("realtime_results.html", results=results, graph_data=graph_data)

        except Exception as e:
            flash(f"Error during capture: {e}", "danger")
            return redirect(url_for("dashboard"))

    # GET request simply renders the page with the form
    return render_template("realtime.html", active_interfaces=active_interfaces)



@app.route("/pcap-analysis", methods=["GET"])
@login_required
def pcap_analysis():
    return render_template("pcap.html")


@app.route("/process-pcap", methods=["GET", "POST"])
@login_required
def process_pcap_file():
    if request.method == "POST":
        if 'pcap_file' not in request.files:
            flash("No archive selected.", "danger")
            return redirect(url_for("dashboard"))

        file = request.files['pcap_file']
        if file.filename == '':
            flash("No archive selected.", "danger")
            return redirect(url_for("dashboard"))

        try:
            pcap_path = os.path.join("uploads", file.filename)
            os.makedirs("uploads", exist_ok=True)
            file.save(pcap_path)

            clean_previous_files()
            start_zeek_capture(pcap_file=pcap_path)
            data = process_zeek_logs()
            results, graph_data = classify_traffic(data)

            os.remove(pcap_path)

            # Save to database
            result_text = json.dumps(results)
            new_result = PCAPResult(result=result_text, user_id=current_user.id)
            db.session.add(new_result)
            db.session.commit()

            flash("PCAP traffic analysed successfully!", "success")
            return render_template("pcap_results.html", results=results, graph_data=graph_data)

        except Exception as e:
            flash(f"Error processing PCAP file: {e}", "danger")
            return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("dashboard"))



@app.route("/evaluate-model", methods=["GET"])
@login_required
def evaluate_model():
    try:
        # Run the evaluation script
        subprocess.run(["python", EVALUATE_SCRIPT], check=True)

        # Load evaluation results
        results_path = "results/model_evaluation.json"
        if os.path.exists(results_path):
            with open(results_path, "r") as f:
                results = json.load(f)

            # Sort feature importances in descending order
            for model_category, models in results.items():
                for model_name, model_data in models.items():
                    if "feature_importance" in model_data and model_data["feature_importance"]:
                        features = model_data["feature_importance"]["features"]
                        importances = model_data["feature_importance"]["importance"]

                        # Create tuples of (feature, importance) and sort them
                        sorted_features = sorted(zip(features, importances), key=lambda x: x[1], reverse=True)

                        # Unpack back to separate lists
                        sorted_feature_names, sorted_importances = zip(*sorted_features)

                        # Store the sorted values back in the results dictionary
                        model_data["feature_importance"]["features"] = list(sorted_feature_names)
                        model_data["feature_importance"]["importance"] = list(sorted_importances)

            flash("Model evaluation completed successfully!", "success")
            evaluation_completed = True

        else:
            flash("Evaluation results not found after execution.", "danger")
            results = None
            evaluation_completed = False

    except subprocess.CalledProcessError as e:
        flash(f"Error during evaluation execution: {e}", "danger")
        return redirect(url_for("dashboard"))
    except json.JSONDecodeError:
        flash("Error parsing evaluation results file.", "danger")
        return redirect(url_for("dashboard"))

    # Render results directly
    return render_template(
        "evaluate_model.html",
        results=results,
        evaluation_completed=evaluation_completed
    )




    
@app.route("/realtime-result/<int:result_id>")
@login_required
def view_realtime_result(result_id):
    """
    Exibir detalhes de um resultado de captura em tempo real.
    """
    result = RealtimeResult.query.filter_by(id=result_id, user_id=current_user.id).first_or_404()

    # Recuperar os resultados salvos no banco
    try:
        print("DEBUG - Raw Result:", result.result)  # Para verificar o conteúdo bruto
        results = json.loads(result.result)  # Lista de pacotes
    except json.JSONDecodeError:
        results = []

    # Criar um DataFrame a partir dos resultados
    import pandas as pd
    data = pd.DataFrame(results)

    # Tradução dos valores de 'label' e 'type' para o esperado pelo `generate_graph_data`
    data["label"] = data["label"].replace({"benigno": "benign", "maligno": "malign"})
    data["type"] = data["type"].replace({"normal": "normal", "Unknown Attack": "Unknown Attack"})

    print("DEBUG - DataFrame Pós-Tradução:", data)  # Para confirmar a tradução dos valores

    # Gerar os dados do gráfico
    graph_data = generate_graph_data_1(data)
    print("DEBUG - Graph Data:", graph_data)  # Para validar os dados do gráfico

    return render_template("realtime_result_details.html", result=result, graph_data=graph_data)


@app.route("/pcap-result/<int:result_id>")
@login_required
def view_pcap_result(result_id):
    """
    Exibir detalhes de um resultado de processamento de arquivo PCAP.
    """
    # Certifique-se de que está buscando no modelo correto
    result = PCAPResult.query.filter_by(id=result_id, user_id=current_user.id).first_or_404()

    # Recuperar os resultados salvos no banco
    try:
        print("DEBUG - Raw Result:", result.result)  # Para verificar o conteúdo bruto
        results = json.loads(result.result)  # Lista de pacotes
    except json.JSONDecodeError:
        results = []

    # Criar um DataFrame a partir dos resultados
    import pandas as pd
    data = pd.DataFrame(results)

    # Tradução dos valores de 'label' e 'type' para o esperado pelo `generate_graph_data`
    data["label"] = data["label"].replace({"benigno": "benign", "maligno": "malign"})
    data["type"] = data["type"].replace({"normal": "normal", "Unknown Attack": "Unknown Attack"})

    print("DEBUG - DataFrame Pós-Tradução:", data)  # Para confirmar a tradução dos valores

    # Gerar os dados do gráfico
    graph_data = generate_graph_data_1(data)
    print("DEBUG - Graph Data:", graph_data)  # Para validar os dados do gráfico

    return render_template("pcap_result_details.html", result=result, graph_data=graph_data)

@app.route("/results")
@login_required
def results():
    pcap_results = PCAPResult.query.filter_by(user_id=current_user.id).all()
    realtime_results = RealtimeResult.query.filter_by(user_id=current_user.id).all()
    return render_template("results.html", pcap_results=pcap_results, realtime_results=realtime_results)


@app.route("/delete-realtime-result/<int:result_id>", methods=["POST"])
@login_required
def delete_realtime_result(result_id):
    """
    Excluir um resultado de captura em tempo real.
    """
    result = RealtimeResult.query.filter_by(id=result_id, user_id=current_user.id).first_or_404()
    db.session.delete(result)
    db.session.commit()
    return redirect(url_for("results"))

@app.route("/delete-pcap-result/<int:result_id>", methods=["POST"])
@login_required
def delete_pcap_result(result_id):
    print(f"DEBUG: Attempting to delete PCAP result with ID {result_id}")  # Add this line
    result = PCAPResult.query.filter_by(id=result_id, user_id=current_user.id).first_or_404()
    db.session.delete(result)
    db.session.commit()
    return redirect(url_for("results"))


@app.route("/pipeline-status", methods=["GET"])
def pipeline_status():
    """Rota para verificar o estado do pipeline."""
    pipeline_state = load_pipeline_state()
    return {"status": pipeline_state}

@app.route("/update-model", methods=["POST"])
@login_required
def update_model():
    """
    Executa o pipeline para combinar CSVs, pré-processar os dados e treinar o modelo.
    """
    try:
        if update_pipeline():
            save_pipeline_state("completed")  # Atualiza o estado para concluído
            flash("Model updated with success!", "success")
        else:
            flash("Error updating model. Check the logs.", "danger")
    except Exception as e:
        save_pipeline_state("error")  # Define como erro em caso de falha
        flash(f"Error updating model: {e}", "danger")
    return redirect(url_for("dashboard"))

@app.route("/delete-all-results", methods=["POST"])
@login_required
def delete_all_results():
    """
    Excluir todos os resultados (PCAP e Tempo Real).
    """
    try:
        # Excluir resultados PCAP
        PCAPResult.query.filter_by(user_id=current_user.id).delete()
        # Excluir resultados em Tempo Real
        RealtimeResult.query.filter_by(user_id=current_user.id).delete()
        # Confirmar alterações
        db.session.commit()
    except Exception as e:
        db.session.rollback()  # Reverter alterações em caso de erro
    return redirect(url_for("dashboard"))

@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    if request.method == "POST":
        user_message = request.form.get("message")
        # Combine raw and final CSVs before extracting context
        try:
            combine_raw_and_final()  # This will create or update real-time/combined_data.csv
        except Exception as e:
            flash(f"Error merging data: {e}", "danger")
            return redirect(url_for("dashboard"))
        # Get detailed context from the combined CSV file
        context_data = get_network_context_from_combined("real-time/combined_data.csv")
        response_message = generate_chatbot_response(user_message, context=context_data)
        return jsonify({"response": response_message})
    else:
        return render_template("chat.html")
    
import json
import pandas as pd

@app.route("/analytics")
@login_required
def analytics():
    # Fetch real-time results
    realtime_results = RealtimeResult.query.filter_by(user_id=current_user.id).all()
    realtime_data = []
    for result in realtime_results:
        try:
            realtime_data.extend(json.loads(result.result))
        except json.JSONDecodeError:
            pass  # Skip if there's an error

    # Fetch PCAP results
    pcap_results = PCAPResult.query.filter_by(user_id=current_user.id).all()
    pcap_data = []
    for result in pcap_results:
        try:
            pcap_data.extend(json.loads(result.result))
        except json.JSONDecodeError:
            pass  # Skip if there's an error

    # Combine both datasets
    combined_data = realtime_data + pcap_data

    # Convert to DataFrame
    df = pd.DataFrame(combined_data)

    # Process the data for anomalies (1) and normal traffic (0)
    df["label"] = df.apply(lambda row: 1 if row['type'] != 'normal' else 0, axis=1)

    # List of anomalies to display in the table
    anomalies = df[df["label"] == 1].to_dict(orient="records")

    return render_template("analytics.html", df=df.to_json(orient="records"), anomalies=anomalies)



@app.route("/download-report")
@login_required
def download_report():
    """Generate and download a properly formatted PDF report."""
    past_results = RealtimeResult.query.filter_by(user_id=current_user.id).all()
    pcap_results = PCAPResult.query.filter_by(user_id=current_user.id).all()

    anomalies = []
    for result in past_results:
        try:
            data = json.loads(result.result)
            anomalies.extend(data)
        except:
            continue

    # Check if no anomalies exist and handle this case
    if not anomalies:
        anomalies = [{"type": "None", "label": "None", "confidence": "N/A", "ts": "N/A"}]

    pdf_path = "analytics_report.pdf"
    c = canvas.Canvas(pdf_path, pagesize=letter)
    
    # Set the title of the document (this is what will show in the file name and title bar)
    c.setTitle("Intelligent Network Security Analysis Report")

    c.setFont("Helvetica", 12)

    # Add Company Header and Information
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "Intelligent Network Security")  # Company Name
    c.setFont("Helvetica", 10)
    c.drawString(100, 730, "Av. das Forças Armadas, 1649-026 Lisboa, Portugal")
    c.drawString(100, 710, "(Phone) 21 790 3000")
    c.drawString(100, 690, "jrpre1@iscte-iul.pt")
    c.drawString(100, 670, "https://www.iscte-iul.pt/")

    # Add Report Title
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, 630, "Analysis Report")

    # Add total anomalies count
    c.setFont("Helvetica", 12)
    total_anomalies = len(anomalies)
    c.drawString(100, 610, f"Total Anomalies: {total_anomalies}")

    # Add Unique Attack Types
    attack_types = set([anomaly.get("type", "Unknown") for anomaly in anomalies])
    c.drawString(100, 590, f"Unique Attack Types: {len(attack_types)}")
    
    # List the different attack types
    y_position = 580
    c.setFont("Helvetica", 10)
    for attack_type in attack_types:
        c.drawString(100, y_position, f"- {attack_type}")
        y_position -= 30

    # Add Summary of Anomalies (Confidence, Timestamp, and Type)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y_position - 20, "Anomalies Details:")
    y_position -= 40  # Increase space between the title and the details
    c.setFont("Helvetica", 10)

    for anomaly in anomalies:
        label = anomaly.get("label", "Unknown")
        attack_type = anomaly.get("type", "Unknown")
        confidence = anomaly.get("confidence", "N/A")
        
        c.drawString(100, y_position, f" Type: {attack_type} | Label: {label} | Confidence: {confidence}")
        y_position -= 20

        # Start a new page if necessary
        if y_position < 100:
            c.showPage()
            c.setFont("Helvetica", 10)
            y_position = 750

    # Add PCAP results to the report
    if pcap_results:
        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, y_position - 20, "PCAP Analysis Details:")
        y_position -= 40
        c.setFont("Helvetica", 10)

        for pcap in pcap_results:
            try:
                data = json.loads(pcap.result)
                for packet in data:
                    timestamp = packet.get("ts", "Unknown")
                    packet_type = packet.get("type", "Unknown")
                    confidence = packet.get("confidence", "N/A")
                    c.drawString(100, y_position, f"Timestamp: {timestamp} | Type: {packet_type} | Confidence: {confidence}")
                    y_position -= 20

                    # Start a new page if necessary
                    if y_position < 100:
                        c.showPage()
                        c.setFont("Helvetica", 10)
                        y_position = 750
            except:
                continue

    c.save()
    return send_file(pdf_path, as_attachment=True)






if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
