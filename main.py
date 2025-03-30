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
from models import db, bcrypt, login_manager, User, PCAPResult, RealtimeResult, ChatContext, ChatMessage, MonitorResult
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
import threading
import webbrowser

# Global dictionaries to track monitoring threads and stop events per user
monitor_threads = {}
monitor_stop_events = {}


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

GLOBAL_UPDATE_FILE = os.path.join(DATASET_DIR, "global_update_time.txt")

def load_global_update_time():
    if os.path.exists(GLOBAL_UPDATE_FILE):
        with open(GLOBAL_UPDATE_FILE, "r") as f:
            try:
                return float(f.read().strip())
            except:
                return 0
    return 0

def save_global_update_time(ts):
    with open(GLOBAL_UPDATE_FILE, "w") as f:
        f.write(str(ts))

def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

def combine_raw_and_final_fixed(raw_csv, final_csv, output_csv):
    """
    Reads raw_csv and final_csv, verifies they have the same number of rows,
    copies the raw data, adds the 'type' and 'label' columns from the final CSV,
    and writes the result to output_csv.
    """
    df_raw = pd.read_csv(raw_csv)
    df_final = pd.read_csv(final_csv)
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

def append_to_csv(existing_path, new_path):
    import pandas as pd
    # Read the existing CSV
    existing_df = pd.read_csv(existing_path)
    # Read the new CSV
    new_df = pd.read_csv(new_path)
    # Concatenate the dataframes
    appended_df = pd.concat([existing_df, new_df], ignore_index=True)
    # Optional: Remove duplicates (if needed)
    appended_df = appended_df.drop_duplicates()
    # Save back to the same file
    appended_df.to_csv(existing_path, index=False)
    return existing_path


import time

def combine_raw_and_final(
    raw_csv="real-time/raw_captured_data.csv", 
    final_csv="real-time/final_captured_data.csv", 
    user_id=None,
    analysis_type="real_time"  # ou "pcap" conforme o caso
):
    import time
    unique_filename = f"combined_data_{analysis_type}_{user_id}_{int(time.time())}.csv"
    output_dir = "analysis"
    # Cria o diretório se não existir
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    output_csv = os.path.join(output_dir, unique_filename)
    
    df_raw = pd.read_csv(raw_csv)
    df_final = pd.read_csv(final_csv)
    
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

# Variável global para armazenar o tempo da última verificação do hash
LAST_HASH_CHECK = None

def check_for_updates(user):
    global LAST_HASH_CHECK
    agora = time.time()
    # Verifica a atualização global apenas se já não tiver sido feita nos últimos 3600 segundos
    if LAST_HASH_CHECK is not None and (agora - LAST_HASH_CHECK) < 3600:
        print("DEBUG: Checagem global de dataset pulada (executada recentemente)")
    else:
        LAST_HASH_CHECK = agora  # Atualiza a checagem global
        print("\n--- Verificando atualizações no dataset ---")
        current_hash = calculate_dataset_hash()
        previous_hash = load_previous_hash()
        pipeline_state = load_pipeline_state()
        print(f"DEBUG: Hash atual: {current_hash}, Hash anterior: {previous_hash}, Estado do pipeline: {pipeline_state}")
        if current_hash != previous_hash:
            print("Novos dados detectados!")
            save_current_hash(current_hash)
            save_pipeline_state("pending")  # Define como pendente
            save_global_update_time(agora)    # Atualiza o timestamp global
        elif pipeline_state == "pending":
            print("Pipeline pendente de execução.")
        else:
            print("Nenhuma atualização detectada.")
    
    # Compara o timestamp global com o timestamp de atualização do modelo para o usuário
    global_update_time = load_global_update_time()
    if user.last_model_update_time is None or user.last_model_update_time.timestamp() < global_update_time:
        return True
    else:
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
    # Convert to lowercase
    data["label"] = data["label"].astype(str).str.lower()
    # Map all possible synonyms or numeric codes:
    data["label"] = data["label"].replace({
        "benigno": "benign",
        "0": "benign",
        "0.0": "benign",
        "maligno": "malign",
        "1": "malign",
        "1.0": "malign",
        "malicious": "malign",
        # add any other synonyms if needed
    })

    benign_count = data[data["label"] == "benign"].shape[0]
    malign_count = data[data["label"] == "malign"].shape[0]

    # Attack types only among malicious
    if "type" in data.columns and malign_count > 0:
        attack_types = data[data["label"] == "malign"]["type"].value_counts().to_dict()
    else:
        attack_types = {}

    return {
        "benign_count": benign_count,
        "malign_count": malign_count,
        "attack_types": attack_types,
    }



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


# --- Updated Per-User Monitoring Function (Appending to a Single Context File) ---
def monitor_traffic(user_id, interface, admin_password, stop_event, context_name):
    """
    Runs a continuous monitoring loop for a specific user.
    Each cycle:
      - Captures traffic for 20 seconds.
      - Processes and classifies the traffic.
      - Saves a MonitorResult.
      - Combines raw and final CSVs (creates a new combined file).
      - If a ChatContext (with the given context_name) already exists, appends new data to its CSV.
      - Otherwise, creates a new ChatContext.
      - Then waits 40 seconds before the next cycle.
    """
    with app.app_context():
        while not stop_event.is_set():
            try:
                print(f"[Monitoring] Starting capture on interface {interface} for user {user_id} for 20 seconds...")
                clean_previous_files()
                # Capture traffic for 20 seconds.
                start_zeek_capture(interface=interface, duration=20, password=admin_password)
                
                print("[Monitoring] Processing Zeek logs...")
                data = process_zeek_logs()
                
                print("[Monitoring] Classifying traffic...")
                try:
                    results, _ = classify_traffic(data)
                except Exception as e:
                    print(f"[Monitoring] classify_traffic error for user {user_id}: {e}")
                    results = []
                
                # Count malign traffic from the list of packets
                malign_count = sum(1 for pkt in results if pkt.get("label", "").lower() == "malign")
                print(f"[Monitoring] Detected {malign_count} malign packets.")

                # Save the monitoring results as a new MonitorResult
                record = {
                    "results": results,
                    "malign_count": malign_count,
                    "timestamp": datetime.utcnow().isoformat()
                }
                monitor_result = MonitorResult(
                    result=json.dumps(record),
                    user_id=user_id
                )
                db.session.add(monitor_result)
                db.session.commit()
                print("[Monitoring] MonitorResult saved.")

                # Attempt to combine the raw and final CSVs into a new file
                try:
                    print("[Monitoring] Attempting to combine CSVs...")
                    combined_new = combine_raw_and_final(
                        raw_csv="real-time/raw_captured_data.csv",
                        final_csv="real-time/final_captured_data.csv",
                        user_id=user_id,
                        analysis_type="monitor"  # constant for monitoring intervals
                    )
                    print(f"[Monitoring] New combined CSV created at: {combined_new}")
                except Exception as e:
                    print("[Monitoring] Error combining CSVs:", e)
                    combined_new = None

                if combined_new:
                    # Try to fetch an existing ChatContext for monitoring with the given context_name.
                    existing_context = ChatContext.query.filter_by(
                        user_id=user_id,
                        analysis_type="monitor",
                        analysis_name=context_name
                    ).first()

                    if existing_context:
                        try:
                            # Append new data to the existing CSV file.
                            append_to_csv(existing_context.file_path, combined_new)
                            print("[Monitoring] Existing ChatContext file appended successfully.")
                            # Optionally, remove the temporary new combined file.
                            os.remove(combined_new)
                        except Exception as e:
                            print("[Monitoring] Error appending to existing ChatContext:", e)
                            # As a fallback, update the file_path with the new file.
                            existing_context.file_path = combined_new
                            db.session.commit()
                            print("[Monitoring] Existing ChatContext file_path updated (fallback).")
                    else:
                        # No existing context – create one with the provided context name.
                        new_context = ChatContext(
                            user_id=user_id,
                            analysis_type="monitor",
                            result_id=monitor_result.id,  # linking current monitor result
                            file_path=combined_new,
                            analysis_name=context_name
                        )
                        db.session.add(new_context)
                        db.session.commit()
                        print("[Monitoring] New ChatContext created for monitoring.")
                
                if malign_count > 0:
                    print("[Monitoring] Malign traffic detected!")
                else:
                    print("[Monitoring] No malign traffic detected this interval.")
            except Exception as e:
                print(f"[Monitoring] Error: {e}")
            
            # Wait 40 seconds before starting the next monitoring cycle
            print("[Monitoring] Waiting 40 seconds before next capture cycle...")
            time.sleep(40)
        print(f"[Monitoring] Stop signal received. Monitoring for user {user_id} is stopping.")








    
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

        # Login automático após o registro
        login_user(new_user)
        return redirect(url_for("home"))

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
    if current_user.is_authenticated:
        user_id = current_user.id

        # Stop the monitoring thread if it exists
        if user_id in monitor_stop_events:
            monitor_stop_events[user_id].set()
            thread = monitor_threads.get(user_id)
            if thread is not None:
                thread.join(timeout=5)
            monitor_stop_events.pop(user_id, None)
            monitor_threads.pop(user_id, None)

        # Mark monitoring as off in the database
        current_user.monitoring_on = False
        current_user.monitoring_interface = None
        current_user.monitoring_password = None
        db.session.commit()

        # Finally log out the user
        logout_user()

    return redirect(url_for("home"))





@app.route("/dashboard")
@login_required
def dashboard():
    pcap_results = PCAPResult.query.filter_by(user_id=current_user.id).all()
    realtime_results = RealtimeResult.query.filter_by(user_id=current_user.id).all()
    active_interfaces = get_active_interfaces()  # Obtém interfaces ativas
    update_available = check_for_updates(current_user)
    return render_template(
        "dashboard.html",
        pcap_results=pcap_results,
        realtime_results=realtime_results,
        active_interfaces=active_interfaces,
        update_available=update_available
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
        # Get the optional analysis name
        analysis_name = request.form.get("analysis_name") or f"Real-Time Analysis {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        try:
            clean_previous_files()
            start_zeek_capture(interface=interface, duration=duration, password=password)
            data = process_zeek_logs()
            results, graph_data = classify_traffic(data)

            # Save results in the database
            result_text = json.dumps(results)
            new_result = RealtimeResult(result=result_text, user_id=current_user.id)
            db.session.add(new_result)
            db.session.commit()  # new_result.id is now available

            # --- Generate and store context ---
            try:
                combined_file_path = combine_raw_and_final(
                    user_id=current_user.id, 
                    analysis_type="real_time"
                )
                new_context = ChatContext(
                    user_id=current_user.id, 
                    analysis_type="real_time",
                    result_id=new_result.id,
                    file_path=combined_file_path,
                    analysis_name=analysis_name  # Save the custom name
                )
                db.session.add(new_context)
                db.session.commit()
            except Exception as e:
                print("Error creating chat context:", e)
            # --- End New Code ---

            flash("Real-Time traffic analyzed successfully!", "success")
            return render_template("realtime_results.html", 
                                results=results, 
                                graph_data=graph_data,
                                result_id=new_result.id)


        except Exception as e:
            flash(f"Error during capture: {e}", "danger")
            return redirect(url_for("dashboard"))

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

        # Get the optional analysis name from the form
        analysis_name = request.form.get("analysis_name") or f"PCAP Analysis {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

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
            db.session.commit()  # new_result.id is now available

            # --- Generate and store context ---
            try:
                combined_file_path = combine_raw_and_final(user_id=current_user.id, analysis_type="pcap")
                new_context = ChatContext(
                    user_id=current_user.id,
                    analysis_type="pcap",
                    result_id=new_result.id,
                    file_path=combined_file_path,
                    analysis_name=analysis_name  # Save the custom name
                )
                db.session.add(new_context)
                db.session.commit()
            except Exception as e:
                print("Error creating chat context:", e)
            # --- End New Code ---

            flash("PCAP traffic analyzed successfully!", "success")
            return render_template("pcap_results.html", 
                                results=results, 
                                graph_data=graph_data,
                                result_id=new_result.id)

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
    import os, json, pandas as pd
    # 1) Retrieve the RealtimeResult object from the database
    result = RealtimeResult.query.filter_by(id=result_id, user_id=current_user.id).first_or_404()

    # 2) Generate graph data from the JSON result (which works correctly)
    try:
        json_results = json.loads(result.result)  # List of packets from JSON
    except json.JSONDecodeError:
        json_results = []
    data_json = pd.DataFrame(json_results)
    # Normalize label/type values for graph generation
    data_json["label"] = data_json["label"].replace({
        "benigno": "benign",
        "maligno": "malign"
    })
    data_json["type"] = data_json["type"].replace({
        "normal": "normal",
        "Unknown Attack": "Unknown Attack"
    })
    graph_data = generate_graph_data_1(data_json)

    # 3) Retrieve the combined CSV for the detailed table from ChatContext
    context = ChatContext.query.filter_by(
        user_id=current_user.id,
        analysis_type="real_time",
        result_id=result_id
    ).order_by(ChatContext.timestamp.desc()).first()

    if not context or not os.path.exists(context.file_path):
        flash("Combined CSV not found for this result.", "danger")
        return redirect(url_for("dashboard"))

    data_csv = pd.read_csv(context.file_path)

    # 4) Prepare the detailed table columns
    detail_columns = [
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service',
        'src_bytes', 'dst_bytes', 'conn_state', 'missed_bytes',
        'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes'
    ]
    # Ensure all required columns exist; if missing, create them with a default value (None)
    for col in detail_columns:
        if col not in data_csv.columns:
            data_csv[col] = None

    detailed_stats = data_csv[detail_columns].head(10).to_dict(orient='records')

    # 5) Render the template with both graph_data and detailed_stats
    return render_template(
        "realtime_result_details.html",
        result=result,
        graph_data=graph_data,
        detailed_stats=detailed_stats
    )


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



@app.route("/realtime-statistics/<int:result_id>")
@login_required
def realtime_statistics(result_id):
    import os, pandas as pd, numpy as np
    # Get the ChatContext to locate the combined CSV file
    context = ChatContext.query.filter_by(
        user_id=current_user.id,
        analysis_type="real_time",
        result_id=result_id
    ).order_by(ChatContext.timestamp.desc()).first()

    if not context or not os.path.exists(context.file_path):
        flash("Combined CSV not found for this result.", "danger")
        return redirect(url_for("dashboard"))

    data = pd.read_csv(context.file_path)

    # Define all the features you want to include in the statistics:
    features_to_plot = [
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service',
        'src_bytes', 'dst_bytes', 'conn_state', 'missed_bytes',
        'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes'
    ]
    
    stats = {}
    for feature in features_to_plot:
        if feature in data.columns:
            # If the feature is numeric, generate histogram data; otherwise, use frequency counts.
            if np.issubdtype(data[feature].dtype, np.number):
                # Compute histogram with 10 bins
                counts, bin_edges = np.histogram(data[feature].dropna(), bins=10)
                stats[feature] = {
                    "type": "numeric",
                    "counts": counts.tolist(),
                    "bin_edges": bin_edges.tolist()
                }
            else:
                # Compute frequency counts and take top 10 categories.
                value_counts = data[feature].value_counts().head(10).to_dict()
                stats[feature] = {
                    "type": "categorical",
                    "counts": value_counts
                }
        else:
            stats[feature] = None

    return render_template(
        "realtime_statistics.html",
        result_id=result_id,
        stats=stats
    )

@app.route("/pcap-statistics/<int:result_id>")
@login_required
def pcap_statistics(result_id):
    import os, pandas as pd, numpy as np
    # Get the ChatContext for PCAP analyses
    context = ChatContext.query.filter_by(
        user_id=current_user.id,
        analysis_type="pcap",
        result_id=result_id
    ).order_by(ChatContext.timestamp.desc()).first()

    if not context or not os.path.exists(context.file_path):
        flash("Combined CSV not found for this PCAP result.", "danger")
        return redirect(url_for("dashboard"))

    data = pd.read_csv(context.file_path)

    # List the features you want to plot statistics for.
    features_to_plot = [
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service',
        'src_bytes', 'dst_bytes', 'conn_state', 'missed_bytes',
        'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes'
    ]
    
    stats = {}
    for feature in features_to_plot:
        if feature in data.columns:
            # For numeric features, generate histogram data; for others, use frequency counts.
            if np.issubdtype(data[feature].dtype, np.number):
                counts, bin_edges = np.histogram(data[feature].dropna(), bins=10)
                stats[feature] = {
                    "type": "numeric",
                    "counts": counts.tolist(),
                    "bin_edges": bin_edges.tolist()
                }
            else:
                value_counts = data[feature].value_counts().head(10).to_dict()
                stats[feature] = {
                    "type": "categorical",
                    "counts": value_counts
                }
        else:
            stats[feature] = None

    return render_template(
        "pcap_statistics.html",
        result_id=result_id,
        stats=stats
    )




@app.route("/results")
@login_required
def results():
    pcap_contexts = ChatContext.query.filter_by(
        user_id=current_user.id, analysis_type="pcap"
    ).order_by(ChatContext.timestamp.desc()).all()
    realtime_contexts = ChatContext.query.filter_by(
        user_id=current_user.id, analysis_type="real_time"
    ).order_by(ChatContext.timestamp.desc()).all()
    monitor_contexts = ChatContext.query.filter_by(
        user_id=current_user.id, analysis_type="monitor"
    ).order_by(ChatContext.timestamp.desc()).all()
    return render_template("results.html", 
                           pcap_contexts=pcap_contexts, 
                           realtime_contexts=realtime_contexts,
                           monitor_contexts=monitor_contexts)




@app.route("/delete-realtime-result/<int:result_id>", methods=["POST"])
@login_required
def delete_realtime_result(result_id):
    result = RealtimeResult.query.filter_by(id=result_id, user_id=current_user.id).first_or_404()
    # Delete associated ChatContext(s) (and via cascade, the messages)
    contexts = ChatContext.query.filter_by(
        user_id=current_user.id,
        analysis_type="real_time",
        result_id=result_id
    ).all()
    for ctx in contexts:
        if os.path.exists(ctx.file_path):
            os.remove(ctx.file_path)
        db.session.delete(ctx)
    db.session.delete(result)
    db.session.commit()
    return redirect(url_for("results"))



@app.route("/delete-pcap-result/<int:result_id>", methods=["POST"])
@login_required
def delete_pcap_result(result_id):
    result = PCAPResult.query.filter_by(id=result_id, user_id=current_user.id).first_or_404()
    # Find associated ChatContext(s) for this PCAP result
    contexts = ChatContext.query.filter_by(
        user_id=current_user.id,
        analysis_type="pcap",
        result_id=result_id
    ).all()
    for ctx in contexts:
        if os.path.exists(ctx.file_path):
            os.remove(ctx.file_path)
        db.session.delete(ctx)  # This deletion will cascade to remove ChatMessage records (if configured)
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
    try:
        if update_pipeline():
            save_pipeline_state("completed")  # Atualiza o estado global do pipeline
            current_user.update_model_timestamp()  # Atualiza o timestamp para o usuário atual
        else:
            flash("Error updating model. Check the logs.", "danger")
    except Exception as e:
        save_pipeline_state("error")
        flash(f"Error updating model: {e}", "danger")
    return redirect(url_for("dashboard"))


@app.route("/delete-all-results", methods=["POST"])
@login_required
def delete_all_results():
    try:
        # Delete all PCAP and Real-Time results for the user
        PCAPResult.query.filter_by(user_id=current_user.id).delete()
        RealtimeResult.query.filter_by(user_id=current_user.id).delete()
        
        # Delete all ChatContext records (cascade deletes messages)
        contexts = ChatContext.query.filter_by(user_id=current_user.id).all()
        for ctx in contexts:
            if os.path.exists(ctx.file_path):
                os.remove(ctx.file_path)
            db.session.delete(ctx)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
    return redirect(url_for("dashboard"))



@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    if request.method == "POST":
        user_message = request.form.get("message")
        context_id = request.form.get("context_id")
        
        # Retrieve the context record using the provided context_id or fallback to the latest context.
        if context_id:
            context_record = ChatContext.query.filter_by(id=context_id, user_id=current_user.id).first()
        else:
            context_record = ChatContext.query.filter_by(user_id=current_user.id).order_by(ChatContext.timestamp.desc()).first()

        if not context_record:
            flash("No analysis context available. Run an analysis first.", "danger")
            return redirect(url_for("dashboard"))

        # Save the user message in the database
        new_user_msg = ChatMessage(
            user_id=current_user.id,
            context_id=context_record.id,
            sender="user",
            message=user_message
        )
        db.session.add(new_user_msg)
        db.session.commit()

        # Load context data for the chatbot
        try:
            context_data = get_network_context_from_combined(context_record.file_path)
        except Exception as e:
            flash("Error loading network context.", "danger")
            return redirect(url_for("dashboard"))
        
        response_message = generate_chatbot_response(user_message, context=context_data)
        
        # Save the bot response in the database
        new_bot_msg = ChatMessage(
            user_id=current_user.id,
            context_id=context_record.id,
            sender="bot",
            message=response_message
        )
        db.session.add(new_bot_msg)
        db.session.commit()
        
        return jsonify({"response": response_message})
    else:
        # For GET: allow an optional query parameter to select a context (default to latest)
        selected_context_id = request.args.get("context_id")
        if selected_context_id:
            current_context = ChatContext.query.filter_by(id=selected_context_id, user_id=current_user.id).first()
        else:
            current_context = ChatContext.query.filter_by(user_id=current_user.id).order_by(ChatContext.timestamp.desc()).first()
        
        if current_context:
            chat_messages = ChatMessage.query.filter_by(
                user_id=current_user.id,
                context_id=current_context.id
            ).order_by(ChatMessage.timestamp.asc()).all()
        else:
            chat_messages = []
        
        user_contexts = ChatContext.query.filter_by(user_id=current_user.id).order_by(ChatContext.timestamp.desc()).all()
        return render_template("chat.html", contexts=user_contexts, messages=chat_messages, current_context=current_context)


    
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
    df = pd.DataFrame(combined_data)

    if not df.empty and 'type' in df.columns:
        # Process the data for anomalies (1) and normal traffic (0)
        df["label"] = df.apply(lambda row: 1 if row['type'] != 'normal' else 0, axis=1)
        anomalies = df[df["label"] == 1].to_dict(orient="records")
    else:
        df = pd.DataFrame()
        anomalies = []

    # Compute distribution of attack types among anomalies
    attack_distribution = {}
    for row in anomalies:
        attack = row.get("type", "unknown")
        attack_distribution[attack] = attack_distribution.get(attack, 0) + 1

    return render_template(
        "analytics.html", 
        df=df.to_json(orient="records"), 
        anomalies=anomalies,
        attack_distribution=json.dumps(attack_distribution)
    )


@app.route("/download-report")
@login_required
def download_report():
    import matplotlib
    matplotlib.use('Agg')  # Non-GUI backend
    import matplotlib.pyplot as plt
    from textwrap import wrap
    import re

    # Combine anomalies from RealTimeResult & PCAPResult
    past_results = RealtimeResult.query.filter_by(user_id=current_user.id).all()
    pcap_results = PCAPResult.query.filter_by(user_id=current_user.id).all()
    all_packets = []
    for result in past_results + pcap_results:
        try:
            data = json.loads(result.result)
            all_packets.extend(data)
        except:
            continue

    # --- Filter out rows whose 'type' == 'normal' to match your /analytics logic ---
    anomalies = [pkt for pkt in all_packets if pkt.get('type', 'unknown').lower() != 'normal']
    total_anomalies = len(anomalies)

    # Attack distribution for anomalies only
    attack_distribution = {}
    for anomaly in anomalies:
        attack = anomaly.get("type", "unknown").lower()
        attack_distribution[attack] = attack_distribution.get(attack, 0) + 1

    # Generate bar chart with matplotlib
    fig, ax = plt.subplots()
    types = list(attack_distribution.keys())
    counts = list(attack_distribution.values())
    ax.bar(types, counts, color='skyblue')
    ax.set_xlabel('Attack Type')
    ax.set_ylabel('Count')
    ax.set_title('Attack Distribution (Anomalies Only)')
    plt.tight_layout()
    chart_path = "attack_chart.png"
    plt.savefig(chart_path)
    plt.close()

    # Chatbot for recommendations
    prompt = (
        f"Attack distribution: {attack_distribution}.\n"
        "If there are no anomalous attacks (i.e. if 'normal' is the only traffic), then the network appears safe—please provide minimal, best-practice security recommendations to maintain this safety. "
        "Otherwise, if there are anomalous attacks, please provide detailed security recommendations and cautions to prevent these types of attacks in the future."
    )

    recommendations = generate_chatbot_response(prompt)

    # Remove simple Markdown bold: **text** => text
    recommendations = re.sub(r'\*\*(.*?)\*\*', r'\1', recommendations)

    # Generate PDF with ReportLab
    pdf_path = "analytics_report.pdf"
    c = canvas.Canvas(pdf_path, pagesize=letter)

    # Header
    c.setTitle("Intelligent Network Security Analysis Report")
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "Intelligent Network Security")
    c.setFont("Helvetica", 10)
    c.drawString(100, 730, "Av. das Forças Armadas, 1649-026 Lisboa, Portugal")
    c.drawString(100, 710, "+351 968 714 451")
    c.drawString(100, 690, "jrpre1@iscte-iul.pt")
    c.drawString(100, 670, "https://www.iscte-iul.pt/")

    # Report Title
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, 630, "Analysis Report")
    c.setFont("Helvetica", 12)
    c.drawString(100, 610, f"Total Anomalies: {total_anomalies}")
    c.drawString(100, 590, f"Unique Attack Types: {len(attack_distribution)}")

    # Embed bar chart
    c.drawImage(chart_path, 100, 400, width=400, height=200)

    # Recommendations heading
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, 370, "Recommendations:")

    # Switch back to normal font for the text
    c.setFont("Helvetica", 10)
    text_x = 100
    text_y = 350
    line_height = 14

    recommendation_lines = recommendations.split("\n")
    for line in recommendation_lines:
        wrapped = wrap(line, width=90)
        if not wrapped:  # if line is empty, add a blank line
            wrapped = [""]
        for subline in wrapped:
            if text_y < 50:  # start a new page if near the bottom
                c.showPage()
                c.setFont("Helvetica", 10)
                text_y = 750
            c.drawString(text_x, text_y, subline)
            text_y -= line_height

    c.save()

    # Remove chart image
    if os.path.exists(chart_path):
        os.remove(chart_path)

    return send_file(pdf_path, as_attachment=True)

@app.route("/monitor", methods=["GET", "POST"])
@login_required
def monitor():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "start":
            interface = request.form.get("interface")
            admin_password = request.form.get("admin_password")
            # Read from the drop-down and the "new context" text field.
            context_select = request.form.get("context_select")
            new_context = request.form.get("new_context")

            # Decide which context name to use: prefer new_context if provided; otherwise, the drop‑down value.
            if new_context and new_context.strip():
                context_name = new_context.strip()
            elif context_select and context_select.strip():
                context_name = context_select.strip()
            else:
                # If nothing is provided, you can default to a new name
                context_name = f"Monitor_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

            current_user.monitoring_on = True
            current_user.monitoring_interface = interface
            current_user.monitoring_password = admin_password
            db.session.commit()

            # Start the per-user monitoring thread with context_name as an argument
            stop_event = threading.Event()
            monitor_stop_events[current_user.id] = stop_event
            monitoring_thread = threading.Thread(
                target=monitor_traffic,
                args=(current_user.id, interface, admin_password, stop_event, context_name)
            )
            monitoring_thread.daemon = True
            monitoring_thread.start()
            monitor_threads[current_user.id] = monitoring_thread

            flash("24/7 monitoring started successfully!", "success")
        elif action == "stop":
            # Stop the monitoring thread if it exists
            if current_user.id in monitor_stop_events:
                monitor_stop_events[current_user.id].set()
                thread = monitor_threads.get(current_user.id)
                if thread is not None:
                    thread.join(timeout=5)
                monitor_stop_events.pop(current_user.id, None)
                monitor_threads.pop(current_user.id, None)
            # Mark monitoring as off in the user record
            current_user.monitoring_on = False
            current_user.monitoring_interface = None
            current_user.monitoring_password = None
            db.session.commit()
            flash("Monitoring stopped.", "success")

    # For GET: also query the user's existing monitor contexts
    existing_contexts = ChatContext.query.filter_by(
        user_id=current_user.id, analysis_type="monitor"
    ).order_by(ChatContext.timestamp.desc()).all()

    active_monitoring = current_user.monitoring_on
    active_interfaces = get_active_interfaces()
    return render_template("monitor.html",
                           active_interfaces=active_interfaces,
                           active_monitoring=active_monitoring,
                           existing_contexts=existing_contexts)




@app.route("/monitor-dashboard", methods=["GET"])
@login_required
def monitor_dashboard():
    # Retrieve all monitoring records in chronological order
    records = MonitorResult.query.filter_by(
        user_id=current_user.id
    ).order_by(MonitorResult.timestamp.asc()).all()

    # If no records, just return empty stats
    if not records:
        summary_stats = {
            "time_monitored": "00:00:00",
            "total_malign": 0,
            "average_malign_per_hour": 0
        }
        return render_template(
            "monitor_dashboard.html",
            timestamps=[],
            traffic_counts=[],
            summary_stats=summary_stats,
            monitor_results=[]
        )

    num_records = len(records)

    # --- 1) TIME MONITORED (string) ---
    # Each record is 20s. total_seconds = num_records * 20
    total_seconds = num_records * 20
    hours = total_seconds // 3600
    remainder = total_seconds % 3600
    minutes = remainder // 60
    seconds = remainder % 60
    time_monitored_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    # --- 2) Build lists for charting and for counting malign ---
    timestamps = []
    traffic_counts = []  # total packets each interval
    malign_list = []     # malign_count each interval

    for rec in records:
        try:
            data = json.loads(rec.result)  # => { "results": [...], "malign_count": X, "timestamp": ...}
            traffic_count = len(data.get("results", []))
            malign_count = data.get("malign_count", 0)
            timestamps.append(rec.timestamp.strftime("%Y-%m-%d %H:%M:%S"))
            traffic_counts.append(traffic_count)
            malign_list.append(malign_count)
        except Exception as e:
            print(f"Error parsing MonitorResult {rec.id}: {e}")
            # Skip this record if there's an error
            continue

    total_malign = sum(malign_list)

    # --- 3) Compute average malign per hour ---
    total_hours = total_seconds / 3600.0
    if total_hours > 0:
        average_malign_per_hour = round(total_malign / total_hours, 2)
    else:
        average_malign_per_hour = 0

    summary_stats = {
        "time_monitored": time_monitored_str,    # e.g. "00:05:20"
        "total_malign": total_malign,
        "average_malign_per_hour": average_malign_per_hour
    }

    return render_template(
        "monitor_dashboard.html",
        timestamps=timestamps,
        traffic_counts=traffic_counts,   # for your line chart
        summary_stats=summary_stats,
        monitor_results=records
    )




@app.route("/monitor-statistics", methods=["GET"])
@login_required
def monitor_statistics():
    import os, pandas as pd, numpy as np
    
    # 1) Find the single ChatContext for the user with analysis_type="monitor".
    #    If you want the *latest* one, order_by timestamp desc. If you only ever create one,
    #    you can just do .first() or .order_by(...).first().
    context = ChatContext.query.filter_by(
        user_id=current_user.id,
        analysis_type="monitor"
    ).order_by(ChatContext.timestamp.desc()).first()

    if not context or not os.path.exists(context.file_path):
        flash("No monitor context file found.", "info")
        return render_template("monitor_statistics.html", stats={}, benign_malign_counts={}, graph_data={})

    # 2) Read the appended CSV file from context.file_path
    df = pd.read_csv(context.file_path)
    print("DEBUG - Monitor CSV shape:", df.shape)
    print("DEBUG - Monitor CSV columns:", df.columns.tolist())

    # 3) Force numeric conversion if needed, like you do for real-time:
    numeric_candidates = [
        'src_port', 'dst_port',
        'missed_bytes',
        'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes'
    ]

    for col in numeric_candidates:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # 4) Define the features to plot (like you do in real-time_statistics.html)
    features_to_plot = [
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service',
        'conn_state', 'missed_bytes',
        'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes'
    ]

    # 5) Build stats dictionary
    stats = {}
    for feature in features_to_plot:
        if feature not in df.columns:
            stats[feature] = None
            continue
        if np.issubdtype(df[feature].dtype, np.number):
            counts, bin_edges = np.histogram(df[feature].dropna(), bins=10)
            stats[feature] = {
                "type": "numeric",
                "counts": counts.tolist(),
                "bin_edges": bin_edges.tolist()
            }
        else:
            value_counts = df[feature].value_counts().head(10).to_dict()
            stats[feature] = {
                "type": "categorical",
                "counts": value_counts
            }

    # 6) Compute Benign vs. Malign distribution (like you do for real-time)
    benign_malign_counts = {"benign": 0, "malign": 0}
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.lower()
        benign_count = (df["label"] == "benign").sum()
        malign_count = (df["label"] == "malign").sum()
        benign_malign_counts = {"benign": int(benign_count), "malign": int(malign_count)}

    # 7) Generate overall graph_data (for your pie chart, attack types, etc.)
    graph_data = generate_graph_data_1(df)

    # 8) Render your template
    return render_template(
        "monitor_statistics.html",
        stats=stats,
        benign_malign_counts=benign_malign_counts,
        graph_data=graph_data
    )


@app.route("/stop_monitor", methods=["POST"])
@login_required
def stop_monitor():
    """
    An alternative endpoint to stop monitoring manually.
    """
    user_id = current_user.id
    if user_id in monitor_stop_events:
        monitor_stop_events[user_id].set()
        thread = monitor_threads.get(user_id)
        if thread is not None:
            thread.join(timeout=5)
        monitor_stop_events.pop(user_id, None)
        monitor_threads.pop(user_id, None)
        flash("Monitoring stopped successfully.", "success")
    else:
        flash("No active monitoring found.", "info")
    return redirect(url_for("monitor"))

@app.route("/delete-monitor-context/<int:context_id>", methods=["POST"])
@login_required
def delete_monitor_context(context_id):
    # Fetch the monitoring context (analysis_type="monitor") for the current user
    context = ChatContext.query.filter_by(
        id=context_id,
        user_id=current_user.id,
        analysis_type="monitor"
    ).first_or_404()

    # Remove the associated CSV file if it exists
    if os.path.exists(context.file_path):
        os.remove(context.file_path)

    # Delete the context record from the database
    db.session.delete(context)
    db.session.commit()
    flash("Monitoring context deleted successfully.", "success")
    return redirect(url_for("results"))

# Route to view a monitor context (with statistics)
@app.route("/view-monitor-context/<int:context_id>")
@login_required
def view_monitor_context(context_id):
    # Fetch the monitoring context for the current user
    context = ChatContext.query.filter_by(
        id=context_id,
        user_id=current_user.id,
        analysis_type="monitor"
    ).first_or_404()
    
    # Build absolute file path if necessary
    full_path = context.file_path
    if not os.path.isabs(full_path):
        full_path = os.path.join(app.root_path, full_path)
    
    if not os.path.exists(full_path):
        flash("Context file not found.", "danger")
        return redirect(url_for("results"))
    
    # Read the CSV file from the context
    df = pd.read_csv(full_path)
    
    # Force numeric conversion on known numeric columns
    numeric_candidates = [
        'src_port', 'dst_port',
        'src_bytes', 'dst_bytes', 'missed_bytes',
        'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes'
    ]

    for col in numeric_candidates:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # Build statistics for each feature (as in monitor_statistics)
    features_to_plot = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service',
                        'src_bytes', 'dst_bytes', 'conn_state', 'missed_bytes',
                        'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes']
    stats = {}
    for feature in features_to_plot:
        if feature not in df.columns:
            stats[feature] = None
            continue
        if np.issubdtype(df[feature].dtype, np.number):
            counts, bin_edges = np.histogram(df[feature].dropna(), bins=10)
            stats[feature] = {
                "type": "numeric",
                "counts": counts.tolist(),
                "bin_edges": bin_edges.tolist()
            }
        else:
            value_counts = df[feature].value_counts().head(10).to_dict()
            stats[feature] = {
                "type": "categorical",
                "counts": value_counts
            }
    
    # Compute benign vs. malicious counts (if the "label" column exists)
    benign_malign_counts = {"benign": 0, "malign": 0}
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.lower()
        benign_count = (df["label"] == "benign").sum()
        malign_count = (df["label"] == "malign").sum()
        benign_malign_counts = {"benign": int(benign_count), "malign": int(malign_count)}
    
    # Generate overall graph data using our helper function
    graph_data = generate_graph_data_1(df)
    
    # Render the view with all the computed stats and graphs
    return render_template("view_monitor_context.html",
                           context=context,
                           stats=stats,
                           benign_malign_counts=benign_malign_counts,
                           graph_data=graph_data)





if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Reset monitoring flags for all users on startup
        users = User.query.all()
        for user in users:
            user.monitoring_on = False
            user.monitoring_interface = None
            user.monitoring_password = None
        db.session.commit()

    threading.Timer(1, lambda: webbrowser.open_new("http://127.0.0.1:5000")).start()
    app.run(debug=True)


