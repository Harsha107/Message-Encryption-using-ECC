import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from flask import Flask, request, jsonify

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

# Streamlit Receiver App
st.title("ECC Receiver Application")

# Generate receiver's key pair
if "receiver_private_key" not in st.session_state:
    st.session_state.receiver_private_key, st.session_state.receiver_public_key = generate_key_pair()

# Display receiver's public key
st.subheader("Your Public Key (Share this with the Sender):")
receiver_public_key_pem = serialize_public_key(st.session_state.receiver_public_key).decode()
st.text_area("Receiver Public Key", receiver_public_key_pem, height=200)

# Flask API to receive encrypted data from the sender
app = Flask(__name__)

@app.route('/receive', methods=['POST'])
def receive_data():
    data = request.json
    sender_public_key_pem = data.get("sender_public_key")
    ciphertext_hex = data.get("ciphertext")
    iv_hex = data.get("iv")
    tag_hex = data.get("tag")

    if not sender_public_key_pem or not ciphertext_hex or not iv_hex or not tag_hex:
        return jsonify({"error": "Invalid data received."}), 400

    try:
        sender_public_key = deserialize_public_key(sender_public_key_pem.encode('utf-8'))
        plaintext = decrypt_message(
            st.session_state.receiver_private_key,
            sender_public_key,
            bytes.fromhex(iv_hex),
            bytes.fromhex(ciphertext_hex),
            bytes.fromhex(tag_hex)
        )

        return jsonify({"plaintext": plaintext.decode('utf-8')}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
