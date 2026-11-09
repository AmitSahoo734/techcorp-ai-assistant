import os
import requests
from flask import Flask, request, jsonify
from auth import token_required
from validate import validate_input, scan_output

app = Flask(__name__)

# Ollama config — local model endpoint
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

# System prompt loaded from environment (never hardcoded)
SYSTEM_PROMPT = os.environ.get(
    "SYSTEM_PROMPT",
    "You are a helpful internal assistant for TechCorp Ltd. Answer questions about company documentation only."
)


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint — no auth required."""
    return jsonify({"status": "ok", "service": "TechCorp Secure AI Chat"}), 200


@app.route("/token", methods=["POST"])
def get_token():
    """
    Demo token endpoint — issues a JWT for testing.
    In production this would verify credentials first.
    """
    import jwt, datetime
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        return jsonify({"error": "JWT_SECRET not configured"}), 500

    payload = {
        "user": "demo_user",
        "role": "employee",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    return jsonify({"token": token}), 200


@app.route("/chat", methods=["POST"])
@token_required   # ← JWT verification happens here first
def chat():
    """
    Secure chat endpoint.
    Flow: JWT check → Input validation → Ollama call → Output scan → Return
    """
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "Request body must contain 'message' field"}), 400

    user_message = data["message"]

    # ── Layer 1 & 2: Input validation ─────────────────────────────────────────
    is_valid, validation_error = validate_input(user_message)
    if not is_valid:
        return jsonify({
            "error": "Input validation failed",
            "detail": validation_error
        }), 400

    # ── Call Ollama LLM ────────────────────────────────────────────────────────
    try:
        ollama_payload = {
            "model": OLLAMA_MODEL,
            "prompt": f"{SYSTEM_PROMPT}\n\nUser: {user_message}\nAssistant:",
            "stream": False
        }
        response = requests.post(OLLAMA_URL, json=ollama_payload, timeout=180)
        response.raise_for_status()
        model_response = response.json().get("response", "")

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Ollama service unavailable. Ensure Ollama is running."}), 503
    except Exception as e:
        return jsonify({"error": f"Model error: {str(e)}"}), 500

    # ── Layer 3: Output scanning ───────────────────────────────────────────────
    is_safe, output_error = scan_output(model_response)
    if not is_safe:
        return jsonify({
            "error": "Response blocked by output scanner",
            "detail": "The model response contained disallowed content and was not returned."
        }), 200  # 200 because the request was valid; the response was filtered

    return jsonify({
        "response": model_response,
        "user": request.user.get("user", "unknown")
    }), 200


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)