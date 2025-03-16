import jwt
import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET_KEY = "your_secret_key"  # Change this to a secure key

# Generate JWT Token
@app.route("/get_token", methods=["POST"])
def get_token():
    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify({"error": "Missing username"}), 400

    token = jwt.encode(
        {"user": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        SECRET_KEY,
        algorithm="HS256",
    )
    return jsonify({"token": token})


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
