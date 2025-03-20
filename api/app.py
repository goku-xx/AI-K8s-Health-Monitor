import os
import jwt
import datetime
import uuid
import logging
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from werkzeug.security import generate_password_hash, check_password_hash
from prometheus_client import Gauge, generate_latest
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest  # ✅ AI Model for anomaly detection

# ✅ Load environment variables
load_dotenv()

# ✅ Flask App Setup
app = Flask(__name__)
CORS(app)

# ✅ Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("server.log")]
)

# ✅ MongoDB Connection using MONGO_URI
MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    logging.error("❌ Missing MONGO_URI in environment variables!")
    exit(1)

try:
    logging.info("🔗 Connecting to MongoDB...")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()  # Test connection
    db = client.get_default_database()  # Automatically picks DB from URI
    users_collection = db["users"]
    logs_collection = db["predictions"]  # ✅ Store AI predictions
    logging.info("✅ Successfully connected to MongoDB!")
except ConnectionFailure as e:
    logging.error(f"❌ MongoDB Connection Error: {e}")
    exit(1)

# ✅ Secret Keys for JWT Authentication
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "default_refresh_key")

# ✅ Define Prometheus Metrics
cpu_usage = Gauge("k8s_cpu_usage", "CPU Usage of the Kubernetes Cluster")
memory_usage = Gauge("k8s_memory_usage", "Memory Usage of the Kubernetes Cluster")

@app.route("/metrics")
def metrics():
    return Response(generate_latest(), mimetype="text/plain")

@app.route("/")
def home():
    return jsonify({"message": "Welcome to AI-K8s Health Monitor!"})


# ✅ Function to Generate JWT Tokens
def generate_tokens(username):
    """Generates access and refresh tokens for a user."""
    access_token = jwt.encode(
        {"user": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
        SECRET_KEY,
        algorithm="HS256",
    )
    refresh_token = jwt.encode(
        {"user": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7), "jti": str(uuid.uuid4())},
        REFRESH_SECRET_KEY,
        algorithm="HS256",
    )
    return access_token, refresh_token


# ✅ User Registration Endpoint
@app.route("/register", methods=["POST"])
def register():
    """Registers a new user."""
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        if users_collection.find_one({"username": username}):
            return jsonify({"error": "User already exists"}), 400

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        users_collection.insert_one({"username": username, "password": hashed_password})
        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        logging.error(f"❌ Error in registration: {e}")
        return jsonify({"error": "Internal server error"}), 500


# ✅ Token Generation Endpoint
@app.route("/get_token", methods=["POST"])
def get_token():
    """Authenticates user and returns JWT tokens."""
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        user = users_collection.find_one({"username": username})

        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        access_token, refresh_token = generate_tokens(username)
        return jsonify({"access_token": access_token, "refresh_token": refresh_token})

    except Exception as e:
        logging.error(f"❌ Error in token generation: {e}")
        return jsonify({"error": "Internal server error"}), 500


# ✅ Refresh Token Endpoint
@app.route("/refresh", methods=["POST"])
def refresh():
    """Refreshes JWT access token."""
    try:
        data = request.get_json()
        refresh_token = data.get("refresh_token")

        if not refresh_token:
            return jsonify({"error": "Missing refresh token"}), 400

        decoded = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=["HS256"])
        username = decoded["user"]

        access_token, new_refresh_token = generate_tokens(username)
        return jsonify({"access_token": access_token, "refresh_token": new_refresh_token})

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401
    except Exception as e:
        logging.error(f"❌ Error in refresh token: {e}")
        return jsonify({"error": "Internal server error"}), 500


# ✅ Load & Train the AI Model (Anomaly Detection)
def train_model():
    """Train an Isolation Forest model for anomaly detection."""
    data = pd.DataFrame({
        "cpu_usage": [30, 35, 32, 40, 50, 100],  # Normal data + anomaly
        "memory_usage": [200, 220, 210, 250, 260, 500]  # Normal + anomaly
    })

    model = IsolationForest(contamination=0.2)  # Detect anomalies
    model.fit(data)
    return model

ai_model = train_model()


# ✅ AI-Based Prediction Route
@app.route("/predict_ai", methods=["POST"])
def predict_ai():
    """Predict anomalies in Kubernetes cluster health data."""
    data = request.get_json()
    cpu = data.get("cpu_usage")
    memory = data.get("memory_usage")

    if cpu is None or memory is None:
        return jsonify({"error": "Missing CPU or Memory usage data"}), 400

    # Convert to DataFrame & Predict
    prediction = ai_model.predict([[cpu, memory]])
    result = "Anomaly Detected" if prediction[0] == -1 else "Normal"

    # ✅ Store Prediction in MongoDB
    logs_collection.insert_one({"cpu_usage": cpu, "memory_usage": memory, "prediction": result, "timestamp": datetime.datetime.utcnow()})

    return jsonify({"cpu_usage": cpu, "memory_usage": memory, "prediction": result})


# ✅ Run Flask App
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
