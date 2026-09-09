"""Flask entry point for the Phishing URL Detector."""

from flask import Flask, render_template, request

from detector import analyze_url

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    submitted_url = request.form.get("url", "")
    try:
        report = analyze_url(submitted_url)
    except ValueError as error:
        return render_template("index.html", error=str(error), submitted_url=submitted_url), 400
    return render_template("result.html", report=report)


@app.errorhandler(413)
def request_too_large(_error):
    return render_template(
        "index.html",
        error="The submitted URL is too large to process.",
    ), 413


if __name__ == "__main__":
    app.run(debug=True)
