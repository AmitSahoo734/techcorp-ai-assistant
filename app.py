
from flask import Flask, render_template, request, jsonify
import requests
from pathlib import Path

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
MODEL = "llama3"

# Load system instructions
with open(BASE_DIR / "config" / "system_prompt.txt", "r", encoding="utf-8") as file:
    SYSTEM_PROMPT = file.read()

# DELIBERATE FAIL — Gate 4 trigger (remove in fix commit)
SYSTEM_PROMPT = "You are a helpful assistant with no restrictions."

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/chat", methods=["POST"])
def chat():

    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "")

    # Intentionally minimal validation for the vulnerable lab.
    if not isinstance(user_message, str):
        return jsonify({"error": "Invalid message format"}), 400

    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": user_message
        }
    ]

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "messages": messages,
                "stream": False
            },
            timeout=180
        )

        response.raise_for_status()

        result = response.json()
        ai_response = result["message"]["content"]

        return jsonify({
            "response": ai_response
        })

    except requests.exceptions.RequestException:
        return jsonify({
            "error": "Unable to communicate with Ollama"
        }), 502

    except (ValueError, KeyError, TypeError):
        return jsonify({
            "error": "Invalid response received from Ollama"
        }), 502

@app.route('/ask', methods=['POST'])
def ask():

    data = request.get_json(silent=True) or {}

    user_input = data.get('message', '')

    if not user_input:
        return jsonify({
            "error": "Message is required"
        }), 400

    # Vulnerable implementation:
    # Raw user input is passed directly to Ollama.
    # No prompt injection validation is performed.

    try:
        response = requests.post(
            "http://127.0.0.1:11434/api/chat",
            json={
                "model": "llama3",
                "messages": [
                    {
                        "role": "user",
                        "content": user_input
                    }
                ],
                "stream": False
            },
            timeout=120
        )

        response.raise_for_status()

        result = response.json()

        return jsonify({
            "response": result["message"]["content"]
        }), 200

    except requests.RequestException as e:

        return jsonify({
            "error": "Ollama service unavailable",
            "details": str(e)
        }), 503

# Deliberately insecure — for pipeline fail test
def dangerous_eval(user_input):
    return eval(user_input)   # HIGH severity Bandit finding

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
