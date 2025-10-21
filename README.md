# Intelligent Network Security Analysis Platform

This project is an **Intelligent Network Security Analysis Platform** designed to monitor, analyze, and classify network traffic in real-time or from PCAP files. It provides detailed statistics, visualizations, and chatbot-based recommendations for network security.

---

## Features

- **Real-Time Traffic Analysis**: Capture and classify live network traffic.
- **PCAP File Analysis**: Analyze pre-recorded PCAP files for anomalies and attacks.
- **24/7 Monitoring**: Continuous monitoring with periodic traffic analysis and statistics.
- **Statistics and Visualizations**: Generate detailed statistics and graphs for network traffic.
- **Chatbot Integration**: A chatbot provides recommendations and insights based on network analysis.
- **Customizable Models**: Train and evaluate machine learning models for traffic classification.

---

## Folder Structure

### Key Directories and Files

- **`main.py`**: The main Flask application file.
- **`real-time/`**: Contains scripts for real-time traffic analysis.
- **`process/`**: Preprocessing and splitting scripts for dataset preparation.
- **`train/`**: Scripts for training and evaluating machine learning models.
- **`combined_csvs/`**: Stores combined datasets for analysis.
- **`templates/`**: HTML templates for the web interface.
- **`static/`**: Static assets like CSS and JavaScript files.
- **`models.py`**: Defines the database models for the application.
- **`chatbot.py`**: Implements the chatbot logic for recommendations.

---

## Installation

### Prerequisites

- Python 3.9 or higher
- Flask
- Zeek (for network traffic analysis)
- Required Python packages (listed in `requirements.txt`)

### Steps

1. Download Tag

   ```bash
   cd Intelligent-Network-Security-1.0.1
   cd dataset
   ```
Then you will upload the csv files (dataset) present in this OneDrive link into the dataset folder: 
https://1drv.ms/f/c/060eac35122b5005/EoYuAR0Hr-1CjOEMHTV-inUBWyWKtziddlI1sDdIySz3Pw?e=yd2znb

