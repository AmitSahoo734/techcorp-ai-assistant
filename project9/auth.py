import os
import jwt
from functools import wraps
from flask import request, jsonify

def token_required(f):
    """
    Decorator that enforces JWT authentication on any route it wraps.
    Reads JWT from Authorization: Bearer <token> header.
    Returns HTTP 401 if token is missing, expired, or invalid.
    Secret is loaded ONLY from environment variable JWT_SECRET.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        # Return 401 if no token provided
        if not token:
            return jsonify({
                "error": "Authentication required",
                "message": "Missing JWT token. Provide Authorization: Bearer <token>"
            }), 401

        try:
            # Load secret from environment variable ONLY — never hardcoded
            secret = os.environ.get("JWT_SECRET")
            if not secret:
                return jsonify({"error": "Server misconfiguration: JWT_SECRET not set"}), 500

            # Decode and verify the JWT
            payload = jwt.decode(token, secret, algorithms=["HS256"])
            request.user = payload  # Attach decoded payload to request context

        except jwt.ExpiredSignatureError:
            return jsonify({
                "error": "Token expired",
                "message": "Your JWT token has expired. Please request a new one."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "error": "Invalid token",
                "message": "JWT token is invalid or tampered."
            }), 401

        return f(*args, **kwargs)
    return decorated