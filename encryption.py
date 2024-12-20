from Cryptodome.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

# Encrypt with AES; Accept decoded and return encoded
def encrypt_message(key, message):
    key = key.encode()
    enc_cipher = AES.new(key, AES.MODE_ECB)
    plain_text = message.encode()
    plain_text = pad(plain_text, 16)
    enc_message = enc_cipher.encrypt(plain_text)
    return enc_message

# Decrypt messages; Returns decode plaintext
def decrypt_message(key, enc_message):
    key = key.encode()
    dec_cipher = AES.new(key, AES.MODE_ECB)
    dec_message = dec_cipher.decrypt(enc_message)
    dec_message = unpad(dec_message, 16)
    return dec_message.decode()
