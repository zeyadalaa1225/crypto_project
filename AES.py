import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
class AESCipher:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt_message(self, message):
        """Encrypt using AES-CBC"""
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        return iv + ciphertext

    def decrypt_message(self, ciphertext):
        """Decrypt using AES-CBC"""
        iv = ciphertext[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
