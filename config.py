import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGODB_SETTINGS = {"host":os.environ.get("MONGO_URI")}
    SECRET_KEY = os.environ.get('FLASK_KEY')
    DEBUG = os.environ.get("DEBUGING")

    