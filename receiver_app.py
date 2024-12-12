# receiver_app.py
import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from flask import Flask, request, jsonify
from threading import Thread

# Helper functions
def aes_decrypt(key, iv, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_bytes):
    return serialization.load_pem_public_key(public_bytes)

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption'
    ).derive(shared_key)
    return derived_key

def decrypt_message(receiver_private_key, sender_public_key, iv, ciphertext, tag):
    symmetric_key = derive_shared_key(receiver_private_key, sender_public_key)
    plaintext = aes_decrypt(symmetric_key, iv, ciphertext, tag)
    return plaintext

# Flask app to receive data
app = Flask(__name__)
data_store = {
    "sender_public_key": None,
    "ciphertext": None,
    "iv": None,
    "tag": None
}

@app.route('/receive', methods=['POST'])
def receive_data():
    data = request.json
    data_store["sender_public_key"] = data.get("sender_public_key")
    data_store["ciphertext"] = data.get("ciphertext")
    data_store["iv"] = data.get("iv")
    data_store["tag"] = data.get("tag")

    if None in data_store.values():
        return jsonify({"error": "Invalid data received."}), 400

    return jsonify({"message": "Data received successfully."}), 200

def run_flask():
    app.run(debug=False, host="0.0.0.0", port=5000)

# Start Flask server in a separate thread
flask_thread = Thread(target=run_flask)
flask_thread.daemon = True
flask_thread.start()

# Streamlit Receiver App
st.title("ECC Receiver Application")

# Generate receiver's key pair
if "receiver_private_key" not in st.session_state:
    st.session_state.receiver_private_key, st.session_state.receiver_public_key = generate_key_pair()

# Display receiver's public key
st.subheader("Your Public Key (Share this with the Sender):")
receiver_public_key_pem = serialize_public_key(st.session_state.receiver_public_key).decode()
st.text_area("Receiver Public Key", receiver_public_key_pem, height=200)

# Check if data is available in the store
if all(data_store.values()):
    st.subheader("Received Encrypted Data")
    st.write("Sender's Public Key:")
    st.text_area("", data_store["sender_public_key"], height=200)

    try:
        sender_public_key = deserialize_public_key(data_store["sender_public_key"].encode('utf-8'))
        plaintext = decrypt_message(
            st.session_state.receiver_private_key,
            sender_public_key,
            bytes.fromhex(data_store["iv"]),
            bytes.fromhex(data_store["ciphertext"]),
            bytes.fromhex(data_store["tag"])
        )

        st.success("Message decrypted successfully!")
        st.write("Decrypted Message:", plaintext.decode('utf-8'))
    except Exception as e:
        st.error(f"Error decrypting message: {e}")
else:
    st.info("Waiting for encrypted data...")
