import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from sender_app import generate_key_pair, serialize_public_key, deserialize_public_key, decrypt_message

st.title("ECC Receiver Application")

# Generate receiver's key pair
if "receiver_private_key" not in st.session_state:
    st.session_state.receiver_private_key, st.session_state.receiver_public_key = generate_key_pair()

# Display receiver's public key
st.subheader("Your Public Key (Share this with the Sender):")
receiver_public_key_pem = serialize_public_key(st.session_state.receiver_public_key).decode()
st.text_area("Receiver Public Key", receiver_public_key_pem, height=200)

# Input data from sender
sender_public_key_pem = st.text_area("Paste Sender's Public Key (PEM format)")
ciphertext_hex = st.text_area("Ciphertext (Hex)")
iv_hex = st.text_input("IV (Hex)")
tag_hex = st.text_input("Tag (Hex)")

if st.button("Decrypt Message"):
    if sender_public_key_pem and ciphertext_hex and iv_hex and tag_hex:
        try:
            sender_public_key = deserialize_public_key(sender_public_key_pem.encode('utf-8'))
            plaintext = decrypt_message(
                st.session_state.receiver_private_key,
                sender_public_key,
                bytes.fromhex(iv_hex),
                bytes.fromhex(ciphertext_hex),
                bytes.fromhex(tag_hex)
            )

            st.success("Message decrypted successfully!")
            st.write("Decrypted Message:", plaintext.decode('utf-8'))
        except Exception as e:
            st.error(f"Error: {e}")
    else:
        st.error("Please provide all required inputs.")
