from flask import Flask, request, jsonify

app = Flask(__name__)

# Define your API key
API_KEY = "mysecureapikey123"

@app.route("/")
def home():
    return "Flask API is running securely!"

@app.route("/predict", methods=["POST"])
def predict():
    # Get API key from headers
    api_key = request.headers.get("X-API-KEY")

    # Check if API key is valid
    if api_key != API_KEY:
        return jsonify({"error": "Unauthorized. Invalid API Key."}), 403

    data = request.get_json()
    return jsonify({"message": "Prediction service is working!", "data_received": data})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
