import streamlit as st
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import time
import tempfile
import numpy as np

def generate_key():
    return get_random_bytes(16)

def generate_iv(block_size):
    return get_random_bytes(block_size)

def encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext).decode()

def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_data, AES.block_size).decode()

def encrypt_file(file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(file.read(), AES.block_size))

def decrypt_file(file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(file.read()), AES.block_size)

def encrypt_app(app_file, key, iv):
    encrypted_app = encrypt_file(app_file, key, iv)
    return encrypted_app

st.title("Nhóm 6 -Demo Mã hóa AES")

if 'key' not in st.session_state:
    st.session_state.key = generate_key()

if st.button("Tạo khóa mới"):
    st.session_state.key = generate_key()

st.write(f"Khóa được tạo: {st.session_state.key.hex()}")

mode = AES.MODE_CBC

if 'iv' not in st.session_state or st.button("Tạo IV mới"):
    st.session_state.iv = generate_iv(AES.block_size)
st.write(f"Vector khởi tạo (IV): {st.session_state.iv.hex()}")

st.subheader("Mã hóa/Giải mã Văn bản")
plaintext = st.text_area("Nhập văn bản cần mã hóa:", "Môn học cơ sở an toàn thông tin thầy Đinh Tường Duy")

if st.button("Mã hóa Văn bản"):
    start_time = time.time()
    ciphertext = encrypt(plaintext, st.session_state.key, st.session_state.iv)
    end_time = time.time()
    st.session_state.ciphertext = ciphertext
    st.write(f"Văn bản đã mã hóa: {ciphertext}")
    st.write(f"Thời gian mã hóa: {end_time - start_time:.5f} giây")

if 'ciphertext' in st.session_state:
    if st.button("Giải mã Văn bản"):
        start_time = time.time()
        decrypted_text = decrypt(st.session_state.ciphertext, st.session_state.key, st.session_state.iv)
        end_time = timeo.time()
        st.write(f"Văn bản sau khi giải mã: {decrypted_text}")
        st.write(f"Thời gian giải mã: {end_time - start_time:.5f} giây")

st.subheader("Mã hóa/Giải mã Tệp")
uploaded_file = st.file_uploader("Chọn tệp để mã hóa/giải mã", type=['txt', 'pdf', 'doc', 'docx', 'exe'])

if uploaded_file is not None:
    if st.button("Mã hóa Tệp"):
        start_time = time.time()
        encrypted_file = encrypt_file(uploaded_file, st.session_state.key, st.session_state.iv)
        end_time = time.time()
        st.download_button(
            label="Tải xuống tệp đã mã hóa",
            data=encrypted_file,
            file_name=f"encrypted_{uploaded_file.name}",
            mime="application/octet-stream"
        )
        st.write(f"Thời gian mã hóa tệp: {end_time - start_time:.5f} giây")

    if st.button("Giải mã Tệp"):
        start_time = time.time()
        decrypted_file = decrypt_file(uploaded_file, st.session_state.key, st.session_state.iv)
        end_time = time.time()
        st.download_button(
            label="Tải xuống tệp đã giải mã",
            data=decrypted_file,
            file_name=f"decrypted_{uploaded_file.name}",
            mime="application/octet-stream"
        )
        st.write(f"Thời gian giải mã tệp: {end_time - start_time:.5f} giây")

st.subheader("Mã hóa Ứng dụng")
app_file = st.file_uploader("Chọn ứng dụng để mã hóa (tệp .exe)", type=['exe'])

if app_file is not None:
    if st.button("Mã hóa Ứng dụng"):
        start_time = time.time()
        encrypted_app = encrypt_app(app_file, st.session_state.key, st.session_state.iv)
        end_time = time.time()
        st.download_button(
            label="Tải xuống ứng dụng đã mã hóa",
            data=encrypted_app,
            file_name=f"encrypted_{app_file.name}",
            mime="application/octet-stream"
        )
        st.write(f"Thời gian mã hóa ứng dụng: {end_time - start_time:.5f} giây")

    if st.button("Giải mã Ứng dụng"):
        start_time = time.time()
        decrypted_app = decrypt_file(app_file, st.session_state.key, st.session_state.iv)
        end_time = time.time()
        st.download_button(
            label="Tải xuống ứng dụng đã giải mã",
            data=decrypted_app,
            file_name=f"decrypted_{app_file.name}",
            mime="application/octet-stream"
        )
        st.write(f"Thời gian giải mã ứng dụng: {end_time - start_time:.5f} giây")
        st.write("Bạn có thể chạy tệp ứng dụng sau khi giải mã để kiểm tra.")

st.write("\n**Lưu ý về bảo mật:**")
st.write("- AES với chế độ CBC cung cấp mức độ bảo mật cao khi được sử dụng đúng cách.")
st.write("- Đảm bảo rằng khóa và IV được quản lý một cách an toàn.")
st.write("- Không chia sẻ khóa và IV với người không đáng tin cậy.")
st.write("- Trong ứng dụng thực tế, nên sử dụng các phương pháp bảo mật bổ sung để bảo vệ dữ liệu và ứng dụng.")