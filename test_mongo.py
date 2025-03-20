import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()  # Load .env file

MONGO_URI = os.getenv("MONGO_URI")

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    print(client.server_info())  # If successful, it prints MongoDB details.
    print("✅ MongoDB connection successful!")
except Exception as e:
    print(f"❌ MongoDB Connection Failed: {e}")
