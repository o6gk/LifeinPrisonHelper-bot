from flask import Flask, request, jsonify
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

app = Flask(__name__)

PUBLIC_KEY = "c3e8e7b0011f083c48a23b5ee0ea8c3408dd0bf7bf59b93c645fddef63eb798d"


def verify(req):
    signature = req.headers.get("X-Signature-Ed25519")
    timestamp = req.headers.get("X-Signature-Timestamp")
    body = req.data

    try:
        VerifyKey(bytes.fromhex(PUBLIC_KEY)).verify(
            timestamp.encode() + body,
            bytes.fromhex(signature)
        )
        return True
    except BadSignatureError:
        return False


@app.route("/interactions", methods=["POST"])
def interactions():
    if not verify(request):
        return "bad signature", 401

    data = request.json

    # Discord ping
    if data["type"] == 1:
        return jsonify({"type": 1})

    # Slash command
    if data["type"] == 2 and data["data"]["name"] == "say":
        message = data["data"]["options"][0]["value"]

        return jsonify({
            "type": 4,
            "data": {
                "content": message,
                "allowed_mentions": {"parse": []}
            }
        })

    return jsonify({"type": 4, "data": {"content": "Unknown command"}})


if __name__ == "__main__":
    app.run(port=3000)
