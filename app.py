import json
import os
from flask import Flask, request, render_template, jsonify, session
from analyzer import analyze
from enrichment import enrich_iocs
from scoring import score

app = Flask(__name__)
app.secret_key = os.urandom(24)

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
last_result = {}  # store last result for JSON download

@app.route("/")
def index():
    return render_template("upload.html")

@app.route("/analyze", methods=["POST"])
def analyze_email():
    global last_result

    # Validate upload
    if "file" not in request.files:
        return render_template("upload.html", error="No file uploaded.")

    file = request.files["file"]

    if not file.filename.endswith(".eml"):
        return render_template("upload.html", error="Only .eml files are accepted.")

    raw_bytes = file.read()

    if len(raw_bytes) > MAX_FILE_SIZE:
        return render_template("upload.html", error="File too large (max 5MB).")

    if len(raw_bytes) == 0:
        return render_template("upload.html", error="Uploaded file is empty.")

    # Run analysis pipeline
    try:
        result = analyze(raw_bytes)

        if result.get("error"):
            return render_template("upload.html", error=result["error"])

        # Enrich IOCs via VirusTotal
        result["enrichment"] = enrich_iocs(result["iocs"])

        # Score and add verdict
        result = score(result)

        last_result = result

    except Exception as e:
        return render_template("upload.html", error=f"Analysis failed: {str(e)}")

    return render_template("report.html", result=result)

@app.route("/report.json")
def report_json():
    if not last_result:
        return jsonify({"error": "No report generated yet."}), 404
    return jsonify(last_result)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)