import os
import time

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from dotenv import load_dotenv
from cryptography.fernet import Fernet

from models import (
    db,
    User,
    PasswordVault,
    PasswordHistory
)

from analyzer.checker import analyze_password


# =========================================================
# APPLICATION SETUP
# =========================================================

app = Flask(__name__)


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app.config["SECRET_KEY"] = os.getenv(
    "FLASK_SECRET_KEY",
    "development-secret-key"
)


# =========================================================
# AUTO-LOCK CONFIGURATION
# =========================================================

# 2 minutes = 120 seconds
SESSION_TIMEOUT = 120

# Warning shown by frontend
WARNING_TIME = 30


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///password_manager.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


# =========================================================
# VAULT ENCRYPTION CONFIGURATION
# =========================================================

vault_key = os.getenv("VAULT_ENCRYPTION_KEY")

if not vault_key:
    raise RuntimeError(
        "VAULT_ENCRYPTION_KEY is not configured in .env"
    )


try:

    cipher = Fernet(
        vault_key.encode()
    )

except Exception as error:

    raise RuntimeError(
        "Invalid VAULT_ENCRYPTION_KEY in .env"
    ) from error


# =========================================================
# CREATE DATABASE TABLES
# =========================================================

with app.app_context():

    db.create_all()


# =========================================================
# HELPER: CHECK LOGIN
# =========================================================

def user_logged_in():

    return "user_id" in session


# =========================================================
# HELPER: AUTO-LOCK
# =========================================================

@app.before_request
def check_session_timeout():

    # -----------------------------------------------------
    # Routes that don't require authentication
    # -----------------------------------------------------

    public_endpoints = {
        "index",
        "analyze",
        "register",
        "login",
        "static"
    }

    if request.endpoint in public_endpoints:
        return


    # -----------------------------------------------------
    # If user isn't logged in, nothing to check
    # -----------------------------------------------------

    if "user_id" not in session:
        return


    # -----------------------------------------------------
    # Get last activity time
    # -----------------------------------------------------

    current_time = time.time()

    last_activity = session.get(
        "last_activity"
    )


    # -----------------------------------------------------
    # First authenticated request
    # -----------------------------------------------------

    if last_activity is None:

        session["last_activity"] = current_time

        return


    # -----------------------------------------------------
    # Calculate inactivity
    # -----------------------------------------------------

    inactive_time = (
        current_time - last_activity
    )


    # -----------------------------------------------------
    # AUTO LOCK AFTER 2 MINUTES
    # -----------------------------------------------------

    if inactive_time >= SESSION_TIMEOUT:

        session.clear()


        # AJAX / API request
        if request.path.startswith("/authenticate-vault"):
            return jsonify({
                "success": False,
                "error": "Your session expired. Please log in again.",
                "session_expired": True
            }), 401


        if request.path.startswith("/edit-password"):
            return jsonify({
                "success": False,
                "error": "Your session expired. Please log in again.",
                "session_expired": True
            }), 401


        if request.path.startswith("/delete-password"):
            return jsonify({
                "success": False,
                "error": "Your session expired. Please log in again.",
                "session_expired": True
            }), 401


        # Normal browser request
        return redirect(
            url_for("login", expired=1)
        )


    # -----------------------------------------------------
    # User is still active
    #
    # Every authenticated request resets timer
    # -----------------------------------------------------

    session["last_activity"] = current_time


# =========================================================
# HOME / PASSWORD ANALYZER
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# PASSWORD ANALYSIS
# =========================================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    data = request.get_json()

    if not data:

        return jsonify({
            "error": "No data received."
        }), 400


    password = data.get(
        "password",
        ""
    )


    if not isinstance(password, str):

        return jsonify({
            "error": "Invalid password format."
        }), 400


    if not password:

        return jsonify({
            "error": "Password is required."
        }), 400


    results = analyze_password(
        password
    )


    return jsonify(results)


# =========================================================
# USER REGISTRATION
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()


        password = request.form.get(
            "password",
            ""
        )


        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        # -------------------------------------------------
        # Username validation
        # -------------------------------------------------

        if not username:

            return render_template(
                "register.html",
                error="Username is required."
            )


        # -------------------------------------------------
        # Password validation
        # -------------------------------------------------

        if not password:

            return render_template(
                "register.html",
                error="Password is required."
            )


        # -------------------------------------------------
        # Confirm password
        # -------------------------------------------------

        if password != confirm_password:

            return render_template(
                "register.html",
                error="Passwords do not match."
            )


        # -------------------------------------------------
        # Check existing username
        # -------------------------------------------------

        existing_user = User.query.filter_by(
            username=username
        ).first()


        if existing_user:

            return render_template(
                "register.html",
                error="Username already exists."
            )


        # -------------------------------------------------
        # Hash password
        # -------------------------------------------------

        password_hash = generate_password_hash(
            password
        )


        # -------------------------------------------------
        # Create user
        # -------------------------------------------------

        new_user = User(
            username=username,
            password_hash=password_hash,
            role="user"
        )


        db.session.add(
            new_user
        )

        db.session.commit()


        return render_template(
            "register.html",
            success=(
                "Registration successful! "
                "You can now log in."
            )
        )


    return render_template(
        "register.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()


        password = request.form.get(
            "password",
            ""
        )


        # -------------------------------------------------
        # Find user
        # -------------------------------------------------

        user = User.query.filter_by(
            username=username
        ).first()


        # -------------------------------------------------
        # Verify password
        # -------------------------------------------------

        if user and check_password_hash(
            user.password_hash,
            password
        ):

            session.clear()


            session["user_id"] = user.id

            session["username"] = (
                user.username
            )

            session["role"] = (
                user.role
            )


            # Start inactivity timer

            session["last_activity"] = (
                time.time()
            )


            return redirect(
                url_for("dashboard")
            )


        return render_template(
            "login.html",
            error="Invalid username or password."
        )


    return render_template(
        "login.html"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not user_logged_in():

        return redirect(
            url_for("login")
        )


    user_id = session["user_id"]


    # -----------------------------------------------------
    # Count passwords
    # -----------------------------------------------------

    password_count = PasswordVault.query.filter_by(
        user_id=user_id
    ).count()


    # -----------------------------------------------------
    # Recent passwords
    # -----------------------------------------------------

    recent_passwords = PasswordVault.query.filter_by(
        user_id=user_id
    ).order_by(
        PasswordVault.created_at.desc()
    ).limit(5).all()


    return render_template(
        "dashboard.html",
        password_count=password_count,
        recent_passwords=recent_passwords,
        session_timeout=SESSION_TIMEOUT,
        warning_time=WARNING_TIME
    )


# =========================================================
# PASSWORD VAULT
# =========================================================

@app.route("/vault")
def vault():

    if not user_logged_in():

        return redirect(
            url_for("login")
        )


    user_id = session["user_id"]


    # -----------------------------------------------------
    # Only retrieve current user's passwords
    # -----------------------------------------------------

    passwords = PasswordVault.query.filter_by(
        user_id=user_id
    ).order_by(
        PasswordVault.created_at.desc()
    ).all()


    return render_template(
        "vault.html",
        passwords=passwords,
        session_timeout=SESSION_TIMEOUT,
        warning_time=WARNING_TIME
    )


# =========================================================
# ADD PASSWORD
# =========================================================

@app.route(
    "/add-password",
    methods=["POST"]
)
def add_password():

    if not user_logged_in():

        return redirect(
            url_for("login")
        )


    website = request.form.get(
        "website",
        ""
    ).strip()


    username = request.form.get(
        "username",
        ""
    ).strip()


    password = request.form.get(
        "password",
        ""
    )


    # -----------------------------------------------------
    # Validation
    # -----------------------------------------------------

    if not website:

        return redirect(
            url_for("vault")
        )


    if not username:

        return redirect(
            url_for("vault")
        )


    if not password:

        return redirect(
            url_for("vault")
        )


    # -----------------------------------------------------
    # Encrypt password
    # -----------------------------------------------------

    encrypted_password = cipher.encrypt(
        password.encode()
    ).decode()


    # -----------------------------------------------------
    # Create vault record
    # -----------------------------------------------------

    vault_entry = PasswordVault(

        user_id=session["user_id"],

        website=website,

        username=username,

        encrypted_password=encrypted_password

    )


    db.session.add(
        vault_entry
    )


    db.session.commit()


    return redirect(
        url_for("vault")
    )


# =========================================================
# AUTHENTICATE VAULT PASSWORD
# =========================================================

@app.route(
    "/authenticate-vault/<int:password_id>",
    methods=["POST"]
)
def authenticate_vault(password_id):

    if not user_logged_in():

        return jsonify({
            "success": False,
            "error": "Session expired. Please log in again.",
            "session_expired": True
        }), 401


    data = request.get_json()

    if not data:

        return jsonify({
            "success": False,
            "error": "No authentication data received."
        }), 400


    manager_password = data.get(
        "auth_password",
        ""
    )


    if not manager_password:

        return jsonify({
            "success": False,
            "error": "Password Manager password is required."
        }), 400


    # -----------------------------------------------------
    # Get current user
    # -----------------------------------------------------

    user = User.query.get(
        session["user_id"]
    )


    if not user:

        session.clear()

        return jsonify({
            "success": False,
            "error": "User account not found.",
            "session_expired": True
        }), 401


    # -----------------------------------------------------
    # Verify manager login password
    # -----------------------------------------------------

    if not check_password_hash(
        user.password_hash,
        manager_password
    ):

        return jsonify({
            "success": False,
            "error": "Authentication failed."
        }), 401


    # -----------------------------------------------------
    # Find vault entry belonging to user
    # -----------------------------------------------------

    vault_entry = PasswordVault.query.filter_by(
        id=password_id,
        user_id=session["user_id"]
    ).first()


    if not vault_entry:

        return jsonify({
            "success": False,
            "error": "Password entry not found."
        }), 404


    # -----------------------------------------------------
    # Decrypt password
    # -----------------------------------------------------

    try:

        decrypted_password = cipher.decrypt(
            vault_entry.encrypted_password.encode()
        ).decode()

    except Exception:

        return jsonify({
            "success": False,
            "error": "Unable to decrypt password."
        }), 500


    return jsonify({
        "success": True,
        "password": decrypted_password
    })


# =========================================================
# EDIT PASSWORD
# =========================================================

@app.route(
    "/edit-password/<int:password_id>",
    methods=["POST"]
)
def edit_password(password_id):

    if not user_logged_in():

        return jsonify({
            "success": False,
            "error": "Session expired. Please log in again.",
            "session_expired": True
        }), 401


    data = request.get_json()

    if not data:

        return jsonify({
            "success": False,
            "error": "No data received."
        }), 400


    manager_password = data.get(
        "auth_password",
        ""
    )


    website = data.get(
        "website",
        ""
    ).strip()


    username = data.get(
        "username",
        ""
    ).strip()


    new_password = data.get(
        "new_password",
        ""
    )


    # -----------------------------------------------------
    # Validate
    # -----------------------------------------------------

    if not manager_password:

        return jsonify({
            "success": False,
            "error": "Password Manager password is required."
        }), 400


    if not website:

        return jsonify({
            "success": False,
            "error": "Website is required."
        }), 400


    if not username:

        return jsonify({
            "success": False,
            "error": "Username is required."
        }), 400


    if not new_password:

        return jsonify({
            "success": False,
            "error": "New password is required."
        }), 400


    # -----------------------------------------------------
    # Verify manager password
    # -----------------------------------------------------

    user = User.query.get(
        session["user_id"]
    )


    if not user:

        session.clear()

        return jsonify({
            "success": False,
            "error": "User account not found.",
            "session_expired": True
        }), 401


    if not check_password_hash(
        user.password_hash,
        manager_password
    ):

        return jsonify({
            "success": False,
            "error": "Authentication failed."
        }), 401


    # -----------------------------------------------------
    # Find vault entry
    # -----------------------------------------------------

    vault_entry = PasswordVault.query.filter_by(
        id=password_id,
        user_id=session["user_id"]
    ).first()


    if not vault_entry:

        return jsonify({
            "success": False,
            "error": "Password entry not found."
        }), 404


    # -----------------------------------------------------
    # Save old password to history
    # -----------------------------------------------------

    old_password_hash = generate_password_hash(
        cipher.decrypt(
            vault_entry.encrypted_password.encode()
        ).decode()
    )


    history_entry = PasswordHistory(

        user_id=session["user_id"],

        password_hash=old_password_hash

    )


    db.session.add(
        history_entry
    )


    # -----------------------------------------------------
    # Encrypt new password
    # -----------------------------------------------------

    encrypted_password = cipher.encrypt(
        new_password.encode()
    ).decode()


    # -----------------------------------------------------
    # Update vault entry
    # -----------------------------------------------------

    vault_entry.website = website

    vault_entry.username = username

    vault_entry.encrypted_password = (
        encrypted_password
    )


    db.session.commit()


    return jsonify({
        "success": True,
        "message": "Password updated successfully."
    })


# =========================================================
# DELETE PASSWORD
# =========================================================

@app.route(
    "/delete-password/<int:password_id>",
    methods=["POST"]
)
def delete_password(password_id):

    if not user_logged_in():

        return jsonify({
            "success": False,
            "error": "Session expired. Please log in again.",
            "session_expired": True
        }), 401


    data = request.get_json()

    if not data:

        return jsonify({
            "success": False,
            "error": "No data received."
        }), 400


    manager_password = data.get(
        "auth_password",
        ""
    )


    if not manager_password:

        return jsonify({
            "success": False,
            "error": "Password Manager password is required."
        }), 400


    # -----------------------------------------------------
    # Verify manager password
    # -----------------------------------------------------

    user = User.query.get(
        session["user_id"]
    )


    if not user:

        session.clear()

        return jsonify({
            "success": False,
            "error": "User account not found.",
            "session_expired": True
        }), 401


    if not check_password_hash(
        user.password_hash,
        manager_password
    ):

        return jsonify({
            "success": False,
            "error": "Authentication failed."
        }), 401


    # -----------------------------------------------------
    # Find password belonging to current user
    # -----------------------------------------------------

    vault_entry = PasswordVault.query.filter_by(
        id=password_id,
        user_id=session["user_id"]
    ).first()


    if not vault_entry:

        return jsonify({
            "success": False,
            "error": "Password entry not found."
        }), 404


    # -----------------------------------------------------
    # Delete
    # -----------------------------------------------------

    db.session.delete(
        vault_entry
    )


    db.session.commit()


    return jsonify({
        "success": True,
        "message": "Password deleted successfully."
    })


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )