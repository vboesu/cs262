import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")

# Server setup
HOST = os.getenv("HOST", "127.0.0.1")
PORT = os.getenv("PORT", 56789)

# Security
TOKEN_VALIDITY = os.getenv("TOKEN_VALIDITY", 60)  # in minutes
