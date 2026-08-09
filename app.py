from flask import Flask, render_template, request, jsonify
from analyzer.checker import analyze_password

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    password = data.get("password", "")

    result = analyze_password(password)

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)