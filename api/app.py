import os
import jwt
import datetime
import uuid
import logging
import prometheus_client
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from werkzeug.security import generate_password_hash, check_password_hash
from prometheus_client import Gauge, generate_latest
from dotenv import load_dotenv

# ✅ Load environment variables
load_dotenv()

# ✅ Flask App Setup
app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

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
    db = client.get_database()  # Automatically picks DB from URI
    users_collection = db["users"]
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
    """Returns Kubernetes cluster metrics in Prometheus format"""
    cpu_usage.set(30.5)  # Replace with real data from Kubernetes API
    memory_usage.set(512)  # Replace with real data from Kubernetes API
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

# ✅ Secure Prediction Route with JWT Authentication
@app.route("/predict", methods=["POST"])
def predict():
    """Secured route that requires authentication."""
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or Invalid Token"}), 401

    token = auth_header.split("Bearer ")[1]

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        data = request.get_json()
        return jsonify({"message": f"Hello {decoded['user']}, Prediction service is working!", "data_received": data})

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token Expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid Token"}), 401
    except Exception as e:
        logging.error(f"❌ Error in prediction: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ✅ Run Flask App
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
