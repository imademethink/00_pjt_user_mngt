import sqlite3
import logging
import os
import uuid
from datetime import datetime
from flask import Flask, request, jsonify
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from dotenv import load_dotenv

# --- Configuration & Setup ---

load_dotenv() # Load environment variables from .env file

# 1. App Naming and Configuration
APP_NAME = "user_mngt_service"
# DB_NAME = "user_mngt_db.sqlite"
DB_NAME = "data/user_mngt_db.sqlite" # Database file will now be in the data folder
SECRET_KEY = os.getenv('SECRET_KEY', 'default-fallback-secret-key-change-me')
BASE_API_URL = os.getenv('BASE_API_URL', 'http://127.0.0.1:5000')
CONFIRMATION_EXPIRY_SECONDS = 3600 # 1 hour expiry

app = Flask(APP_NAME)
app.config['SECRET_KEY'] = SECRET_KEY

# Token Serializer for confirmation links
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 2. Status Code Constants (Avoid hardcoding)
STATUS_OK = 200
STATUS_CREATED = 201
STATUS_ACCEPTED = 202
STATUS_BAD_REQUEST = 400
STATUS_UNAUTHORIZED = 401
STATUS_FORBIDDEN = 403
STATUS_SERVER_ERROR = 500

# 3. Logging Setup (Debug Mode)
# Check if running in development/debug mode
if os.getenv('FLASK_ENV') == 'development':
    app.config['DEBUG'] = True
    logging.basicConfig(level=logging.DEBUG, 
                        format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    app.logger.setLevel(logging.DEBUG)
    app.logger.debug(f"Application running in DEBUG mode. Database: {DB_NAME}")
else:
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

# --- Database Initialization and Helpers ---

def get_user_mngt_db():
    """Establishes a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row # Allows fetching rows as dictionaries
        return conn
    except sqlite3.Error as e:
        app.logger.error(f"Database connection error: {e}")
        return None

def user_mngt_init_db():
    """Initializes the database schema."""
    conn = get_user_mngt_db()
    if not conn:
        return
    
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_mngt_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE CHECK(LENGTH(email) BETWEEN 5 AND 25),
            password TEXT NOT NULL CHECK(LENGTH(password) = 6),
            confirmation_token TEXT UNIQUE,
            is_confirmed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    app.logger.info("Database schema initialized for user_mngt_users table.")

# Initialize DB on application startup
with app.app_context():
    user_mngt_init_db()

# --- Utility Functions ---

def validate_registration_data(email, password):
    """Performs validation based on SRS."""
    errors = {}
    if not (5 <= len(email) <= 25):
        errors['email'] = "Email must be between 5 and 25 characters."
    if len(password) != 6:
        errors['password'] = "Password must be exactly 6 characters."
    return errors

def create_confirmation_token(email):
    """Generates a URL-safe, time-stamped token."""
    # The payload can just be the user's email
    return serializer.dumps(email, salt='email-confirm-salt')

# --- API Endpoints ---

@app.route('/version', methods=['GET'])
def user_mngt_get_version():
    """API-001: Returns the system version."""
    app.logger.debug("Received request for /version")
    return jsonify({
        "version": "1.0.0",
        "service": APP_NAME
    }), STATUS_OK

@app.route('/register', methods=['POST'])
def user_mngt_register():
    """API-002: Registers a new user (pre-confirmation)."""
    data = request.get_json()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    validation_errors = validate_registration_data(email, password)
    if validation_errors:
        app.logger.warning(f"Registration failed: Validation error for email {email}.")
        return jsonify({"message": "Invalid input format.", "errors": validation_errors}), STATUS_BAD_REQUEST

    conn = get_user_mngt_db()
    if not conn:
        return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR
    
    try:
        # Check if email already exists
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM user_mngt_users WHERE email = ?", (email,))
        if cursor.fetchone():
            app.logger.warning(f"Registration failed: Email already exists: {email}")
            return jsonify({"message": "User with this email already exists."}), STATUS_BAD_REQUEST

        # Generate token and link
        confirmation_token = create_confirmation_token(email)
        confirmation_link = f"{BASE_API_URL}/confirm_registration/{confirmation_token}"
        
        # Insert user record
        cursor.execute(
            "INSERT INTO user_mngt_users (email, password, confirmation_token, created_at) VALUES (?, ?, ?, DATETIME('now'))",
            (email, password, confirmation_token)
        )
        conn.commit()
        app.logger.info(f"User registered successfully (pending confirmation): {email}")

        return jsonify({
            "message": "Registration successful, please click the confirmation link.",
            "confirmation_link": confirmation_link
        }), STATUS_CREATED

    except sqlite3.Error as e:
        app.logger.error(f"Database error during registration for {email}: {e}")
        return jsonify({"message": "Internal server error during registration."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


@app.route('/confirm_registration/<token>', methods=['GET'])
def user_mngt_confirm_registration(token):
    """API-003: Completes user registration using the token."""
    conn = get_user_mngt_db()
    if not conn:
        return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR

    try:
        # 1. Deserialize and validate the token
        try:
            email = serializer.loads(token, salt='email-confirm-salt', max_age=CONFIRMATION_EXPIRY_SECONDS)
        except SignatureExpired:
            app.logger.warning(f"Confirmation failed: Token expired.")
            return jsonify({"message": "Invalid or expired confirmation token."}), STATUS_FORBIDDEN
        except BadTimeSignature:
            app.logger.warning(f"Confirmation failed: Invalid token signature.")
            return jsonify({"message": "Invalid or expired confirmation token."}), STATUS_FORBIDDEN
        except Exception:
            app.logger.warning(f"Confirmation failed: Malformed token.")
            return jsonify({"message": "Invalid or expired confirmation token."}), STATUS_FORBIDDEN
            
        # 2. Update user record in DB
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_mngt_users SET is_confirmed = 1, confirmation_token = NULL WHERE email = ? AND is_confirmed = 0",
            (email,)
        )
        
        if cursor.rowcount == 0:
            # Token was valid but user was already confirmed or email not found/pending
            app.logger.warning(f"Confirmation failed: No pending user found for email {email} or already confirmed.")
            # Check if user is already confirmed
            cursor.execute("SELECT is_confirmed FROM user_mngt_users WHERE email = ?", (email,))
            user_record = cursor.fetchone()
            if user_record and user_record['is_confirmed'] == 1:
                return jsonify({"message": "Registration successfully confirmed. You can now login."}), STATUS_OK
            else:
                 return jsonify({"message": "Invalid or expired confirmation token."}), STATUS_FORBIDDEN


        conn.commit()
        app.logger.info(f"User confirmed registration successfully: {email}")
        return jsonify({"message": "Registration successfully confirmed. You can now login."}), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"Database error during confirmation for token {token}: {e}")
        return jsonify({"message": "Internal server error during confirmation."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


@app.route('/login', methods=['POST'])
def user_mngt_login():
    """API-004: Authenticates user credentials."""
    data = request.get_json()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    # Basic input checks
    if not email or not password:
        return jsonify({"message": "Email and password are required."}), STATUS_BAD_REQUEST

    conn = get_user_mngt_db()
    if not conn:
        return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, is_confirmed FROM user_mngt_users WHERE email = ?", (email,))
        user_record = cursor.fetchone()

        if not user_record:
            app.logger.warning(f"Login failed: User not found for {email}")
            return jsonify({"message": "Invalid email or password."}), STATUS_UNAUTHORIZED

        # 1. Check Password (No encryption required per spec)
        if user_record['password'] != password:
            app.logger.warning(f"Login failed: Invalid password for {email}")
            return jsonify({"message": "Invalid email or password."}), STATUS_UNAUTHORIZED

        # 2. Check Confirmation Status
        if user_record['is_confirmed'] == 0:
            app.logger.warning(f"Login failed: Account not confirmed for {email}")
            return jsonify({"message": "Account not confirmed. Please check your email."}), STATUS_FORBIDDEN

        # Successful Login
        app.logger.info(f"User logged in successfully: {email}")
        return jsonify({
            "message": "Login successful.",
            "user_id": user_record['id']
        }), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"Database error during login for {email}: {e}")
        return jsonify({"message": "Internal server error during login."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


if __name__ == '__main__':
    # Run the application (This will be overridden by Docker/Gunicorn in a real setup)
    app.run(host='0.0.0.0', port=5000, debug=True)