import os
import jwt
import datetime
import uuid
from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from urllib.parse import quote_plus

app = Flask(__name__)

# Secure MongoDB credentials using environment variables
DB_USERNAME = os.getenv("DB_USERNAME", "your-username")
DB_PASSWORD = os.getenv("DB_PASSWORD", "your-password")

# Encode MongoDB credentials to avoid special character issues
ENCODED_USERNAME = quote_plus(DB_USERNAME)
ENCODED_PASSWORD = quote_plus(DB_PASSWORD)

# MongoDB Connection
MONGO_URI = f"mongodb+srv://{ENCODED_USERNAME}:{ENCODED_PASSWORD}@cluster0.bmbqd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client["ai_health_monitor"]  # Database
users_collection = db["users"]  # Users Collection

# Secret keys for JWT
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "your_refresh_secret_key")

# Function to generate tokens
def generate_tokens(username):
    access_token = jwt.encode(
        {
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        },
        SECRET_KEY,
        algorithm="HS256",
    )

    refresh_token = jwt.encode(
        {
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
            "jti": str(uuid.uuid4()),
        },
        REFRESH_SECRET_KEY,
        algorithm="HS256",
    )

    return access_token, refresh_token

# User Registration
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    hashed_password = generate_password_hash(password)

    if users_collection.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 400

    users_collection.insert_one({"username": username, "password": hashed_password, "refresh_token": None})
    return jsonify({"message": "User registered successfully"}), 201

# Generate Access & Refresh Tokens
@app.route("/get_token", methods=["POST"])
def get_token():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = users_collection.find_one({"username": username})

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token, refresh_token = generate_tokens(username)

    users_collection.update_one({"_id": user["_id"]}, {"$set": {"refresh_token": refresh_token}})
    return jsonify({"access_token": access_token, "refresh_token": refresh_token})

# Refresh Token Endpoint
@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.get_json()
    refresh_token = data.get("refresh_token")

    if not refresh_token:
        return jsonify({"error": "Missing refresh token"}), 400

    try:
        decoded = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=["HS256"])
        username = decoded["user"]

        user = users_collection.find_one({"username": username, "refresh_token": refresh_token})
        if not user:
            return jsonify({"error": "Invalid refresh token"}), 401

        access_token, _ = generate_tokens(username)
        return jsonify({"access_token": access_token})

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401

# Secure Predict Route with JWT
@app.route("/predict", methods=["POST"])
def predict():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Missing Token"}), 401

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token Expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid Token"}), 401

    data = request.get_json()
    return jsonify({"message": f"Hello {decoded['user']}, Prediction service is working!", "data_received": data})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
