from flask import Flask, render_template, request
import os
import hashlib
from datetime import datetime

app = Flask(__name__)

# Folder where evidence files will be stored
UPLOAD_FOLDER = "evidence"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def calculate_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


def get_risk(file_size, extension):
    """Simple forensic risk classification."""

    suspicious_extensions = [
        ".exe", ".bat", ".cmd", ".vbs",
        ".ps1", ".scr", ".dll"
    ]

    if extension.lower() in suspicious_extensions:
        return "HIGH"

    if file_size > 10 * 1024 * 1024:
        return "MEDIUM"

    return "LOW"


@app.route("/", methods=["GET", "POST"])
def index():

    result = None

    if request.method == "POST":

        if "evidence_file" not in request.files:
            return render_template(
                "index.html",
                error="No evidence file selected."
            )

        file = request.files["evidence_file"]

        if file.filename == "":
            return render_template(
                "index.html",
                error="Please select an evidence file."
            )

        # Save file
        filename = os.path.basename(file.filename)
        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            filename
        )

        file.save(filepath)

        # File information
        file_size = os.path.getsize(filepath)
        extension = os.path.splitext(filename)[1]

        # SHA-256
        file_hash = calculate_hash(filepath)

        # Modification time
        modified_time = os.path.getmtime(filepath)
        modified = datetime.fromtimestamp(
            modified_time
        ).strftime("%d-%m-%Y %H:%M:%S")

        # Risk
        risk = get_risk(file_size, extension)

        # Status
        if risk == "HIGH":
            status = "SUSPICIOUS"
        else:
            status = "ANALYZED"

        result = {
            "filename": filename,
            "size": round(file_size / 1024, 2),
            "type": extension.upper() if extension else "UNKNOWN",
            "hash": file_hash,
            "modified": modified,
            "status": status,
            "risk": risk
        }

    return render_template(
        "index.html",
        result=result
    )


if __name__ == "__main__":
    app.run(debug=True)