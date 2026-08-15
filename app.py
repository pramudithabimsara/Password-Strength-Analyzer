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

from models import db, User
from analyzer.checker import analyze_password


app = Flask(__name__)

# -----------------------------
# Application Configuration
# -----------------------------

app.config["SECRET_KEY"] = "change-this-to-a-random-secret-key"

# -----------------------------
# Database Configuration
# -----------------------------

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///password_manager.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


# -----------------------------
# Create Database Tables
# -----------------------------

with app.app_context():
    db.create_all()


# -----------------------------
# Home Page
# -----------------------------

@app.route("/")
def index():

    return render_template("index.html")


# -----------------------------
# Password Analysis
# -----------------------------

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No data received."
        }), 400

    password = data.get("password", "")

    if not isinstance(password, str):
        return jsonify({
            "error": "Invalid password format."
        }), 400

    if not password:
        return jsonify({
            "error": "Password is required."
        }), 400

    # Use existing password analyzer
    results = analyze_password(password)

    return jsonify(results)


# -----------------------------
# User Registration
# -----------------------------

@app.route("/register", methods=["GET", "POST"])
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

        # -------------------------
        # Validate Username
        # -------------------------

        if not username:

            return render_template(
                "register.html",
                error="Username is required."
            )

        # -------------------------
        # Validate Password
        # -------------------------

        if not password:

            return render_template(
                "register.html",
                error="Password is required."
            )

        # -------------------------
        # Confirm Password
        # -------------------------

        if password != confirm_password:

            return render_template(
                "register.html",
                error="Passwords do not match."
            )

        # -------------------------
        # Check Existing Username
        # -------------------------

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:

            return render_template(
                "register.html",
                error="Username already exists."
            )

        # -------------------------
        # Hash Password
        # -------------------------

        password_hash = generate_password_hash(
            password
        )

        # -------------------------
        # Create User
        # -------------------------

        new_user = User(
            username=username,
            password_hash=password_hash,
            role="user"
        )

        db.session.add(new_user)
        db.session.commit()

        return render_template(
            "register.html",
            success="Registration successful! You can now log in."
        )

    return render_template("register.html")


# -----------------------------
# Login
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
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

        # Find user
        user = User.query.filter_by(
            username=username
        ).first()

        # Verify username and password
        if user and check_password_hash(
            user.password_hash,
            password
        ):

            # Store login information in session
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    return render_template("login.html")


# -----------------------------
# Dashboard
# -----------------------------

@app.route("/dashboard")
def dashboard():

    # User must be logged in
    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    return f"""
        <!DOCTYPE html>

        <html>

        <head>
            <title>Password Manager Dashboard</title>
        </head>

        <body>

            <h1>🔐 Password Manager</h1>

            <h2>
                Welcome, {session["username"]}!
            </h2>

            <p>
                You are successfully logged in.
            </p>

            <p>
                Role: {session["role"]}
            </p>

            <hr>

            <p>
                Password Vault coming soon...
            </p>

            <a href="{url_for('logout')}">
                Logout
            </a>

        </body>

        </html>
    """


# -----------------------------
# Logout
# -----------------------------

@app.route("/logout")
def logout():

    # Remove all login information
    session.clear()

    return redirect(
        url_for("login")
    )


# -----------------------------
# Run Application
# -----------------------------

if __name__ == "__main__":

    app.run(
        debug=True
    )