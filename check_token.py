import jwt

SECRET_KEY = "your_secret_key"  # This must be the same as in app.py

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ29rdWxnMTJ0aDIwMDQiLCJleHAiOjE3NDIyNDA2NDZ9.TVJO9DtjqeRRoib1VrsO9vfx3FSl9A6Dl2vVpIH1_ks"  # Replace with your actual token

try:
    decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    print("✅ Token is valid:", decoded)
except jwt.ExpiredSignatureError:
    print("❌ Token has expired")
except jwt.InvalidTokenError:
    print("❌ Token is invalid")
