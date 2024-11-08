# Bài Tập Lớn Cơ Sở An Toàn Thông Tin

### Mã Hóa AES

Mã hóa AES (Advanced Encryption Standard) là một tiêu chuẩn mã hóa đối xứng được sử dụng rộng rãi trên toàn thế giới. AES được thiết kế để mã hóa và giải mã dữ liệu một cách an toàn và hiệu quả.

#### Các bước thực hiện:

1. **Khởi tạo**: Tạo khóa bí mật (secret key) để sử dụng trong quá trình mã hóa và giải mã.
2. **Mã hóa**: Sử dụng khóa bí mật để mã hóa dữ liệu gốc thành dữ liệu đã mã hóa.
3. **Giải mã**: Sử dụng khóa bí mật để giải mã dữ liệu đã mã hóa trở lại dữ liệu gốc.

#### Ví dụ mã hóa AES trong Python:

```python
from Crypto.Cipher import AES
import base64

# Hàm mã hóa
def encrypt(key, raw):
   cipher = AES.new(key, AES.MODE_ECB)
   encoded = base64.b64encode(cipher.encrypt(raw))
   return encoded

# Hàm giải mã
def decrypt(key, enc):
   cipher = AES.new(key, AES.MODE_ECB)
   decoded = cipher.decrypt(base64.b64decode(enc))
   return decoded

# Khóa bí mật (phải có độ dài 16, 24 hoặc 32 bytes)
key = b'This is a key123'

# Dữ liệu gốc
data = b'This is some data'

# Mã hóa dữ liệu
encrypted_data = encrypt(key, data)
print(f'Encrypted: {encrypted_data}')

# Giải mã dữ liệu
decrypted_data = decrypt(key, encrypted_data)
print(f'Decrypted: {decrypted_data}')
```

#### Tài liệu tham khảo:

- [Advanced Encryption Standard (AES)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/)