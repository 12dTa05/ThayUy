import os

# MongoDB configuration
MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://Death:DeathA_1205@death.8wudq.mongodb.net/ThayUy?retryWrites=true&w=majority&appName=Death")
MONGO_DB = os.environ.get("MONGO_DB", "ThayUy")
MONGO_COLLECTION = os.environ.get("MONGO_COLLECTION", "scan_reports")

# API configuration
NVD_API_KEY = os.environ.get("NVD_API_KEY", "A2C3AD60-CA13-F011-8359-129478FCB64D")

# Scanning defaults
DEFAULT_PORT_RANGE = "1-1000"
DEFAULT_OUTPUT_FORMAT = "json"

# Timeouts
HTTP_TIMEOUT = 10
CONNECTION_TIMEOUT = 5
API_TIMEOUT = 15

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 2
STATUS_FORCELIST = (500, 502, 504, 429)