import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

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

st.title("ECC Receiver Application")

if "receiver_private_key" not in st.session_state:
    st.session_state.receiver_private_key, st.session_state.receiver_public_key = generate_key_pair()

st.subheader("Your Public Key (Share this with Sender):")
st.text_area("Public Key", serialize_public_key(st.session_state.receiver_public_key).decode(), height=200)

iv_hex = st.text_input("IV (Hex)")
ciphertext_hex = st.text_area("Ciphertext (Hex)")
tag_hex = st.text_input("Tag (Hex)")
sender_public_key_pem = st.text_area("Paste Sender's Public Key (PEM format)")

if st.button("Decrypt Message"):
    if iv_hex and ciphertext_hex and tag_hex and sender_public_key_pem:
        try:
            sender_public_key = deserialize_public_key(sender_public_key_pem.encode())
            plaintext = decrypt_message(
                st.session_state.receiver_private_key,
                sender_public_key,
                bytes.fromhex(iv_hex),
                bytes.fromhex(ciphertext_hex),
                bytes.fromhex(tag_hex)
            )

            st.success("Message decrypted successfully!")
            st.write("Decrypted Message:", plaintext.decode())
        except Exception as e:
            st.error(f"Error: {e}")
    else:
        st.error("Please provide all required details.")
