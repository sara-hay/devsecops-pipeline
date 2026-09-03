from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def index():
    return jsonify({"service": "secops-pipeline-demo", "status": "ok"})


@app.route("/health")
def health():
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    # Debug/host settings intentionally left minimal for now —
    # we'll tighten these up as the pipeline matures.
    app.run(host="0.0.0.0", port=5000)
