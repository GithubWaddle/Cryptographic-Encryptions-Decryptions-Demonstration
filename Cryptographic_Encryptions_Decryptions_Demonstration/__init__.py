from flask import Flask, render_template, request, jsonify
from .aes import aes_encrypt, aes_decrypt
from .tripledes import tripledes_encrypt, tripledes_decrypt
from .rc4 import rc4_encrypt, rc4_decrypt
from .rsa import rsa_encrypt, rsa_decrypt, rsa_generate_keys

app = Flask(__name__)

# RSA key pair storage
rsa_keys = {
    "private": None,
    "public": None
}


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        event = request.headers.get("X-Event")
        data = request.get_json() or {}
        print(data)

        if event == "execute":
            return handle_execute(data)
        elif event == "generatePublicPrivateKeys":
            return handle_key_generation(data)

        return jsonify({})  # Default for unknown events

    return render_template("index.html")


def handle_execute(data):
    mode = data.get("mode")
    input_text = data.get("input")
    algorithm = data.get("algorithm")
    key = data.get("key")

    if not input_text:
        return jsonify({"output": ""})

    if mode == "encrypt":
        output = encrypt(algorithm, input_text, key)
    else:
        output = decrypt(algorithm, input_text, key)

    return jsonify({"output": output})


def handle_key_generation(data):
    algorithm = data.get("algorithm")

    if algorithm == "rsa":
        private_key, public_key = rsa_generate_keys()
        rsa_keys["private"] = private_key
        rsa_keys["public"] = public_key

        return jsonify({
            "privateKey": private_key.export_key().decode(),
            "publicKey": public_key.export_key().decode()
        })

    return jsonify({})


def encrypt(algorithm: str, plaintext: str, key: str) -> str:
    match algorithm:
        case "rsa":
            if not rsa_keys["public"]:
                return ""
            return rsa_encrypt(rsa_keys["public"], plaintext)
        case "aes":
            if not key:
                return ""
            return aes_encrypt(key, plaintext)
        case "3des":
            if not key:
                return ""
            return tripledes_encrypt(key, plaintext)
        case "rc4":
            if not key:
                return ""
            return rc4_encrypt(key, plaintext)
        case _:
            return ""


def decrypt(algorithm: str, ciphertext: str, key: str) -> str:
    match algorithm:
        case "rsa":
            if not rsa_keys["private"]:
                return ""
            return rsa_decrypt(rsa_keys["private"], ciphertext)
        case "aes":
            if not key:
                return ""
            return aes_decrypt(key, ciphertext)
        case "3des":
            if not key:
                return ""
            return tripledes_decrypt(key, ciphertext)
        case "rc4":
            if not key:
                return ""
            return rc4_decrypt(key, ciphertext)
        case _:
            return ""


def main():
    app.run(debug=True)


if __name__ == "__main__":
    main()
