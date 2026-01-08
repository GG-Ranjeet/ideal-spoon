from flask import Flask
from flask_mongoengine import MongoEngine
from mongoengine.connection import get_connection
# Removed the failing import

app = Flask(__name__)

# --- PASTE YOUR URI HERE ---
# Remember to replace <password> with your real password
uri = "mongodb+srv://mongodb:ahgS0eUUrkUh2RKo@clustergg.jdxkxws.mongodb.net/myBlog?appName=ClusterGG"

app.config['MONGODB_SETTINGS'] = {
    'host': uri
}

db = MongoEngine(app)

def test_connection():
    print(f"Testing connection to: {uri.split('@')[1]}") # Prints the cluster part only for safety
    try:
        # 1. Force a connection context
        with app.app_context():
            # 2. Get the raw connection
            conn = get_connection()
            
            # 3. Send the "ping" command
            conn.admin.command('ping')
            
            print("\n✅ SUCCESS: Connected to MongoDB Atlas!")
            print(f"   Database: {db.get_db().name}")

    except Exception as e:
        print("\n❌ FAILED: Could not connect.")
        print(f"   Error details: {e}")

if __name__ == "__main__":
    test_connection()