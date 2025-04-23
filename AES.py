from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AESCipher:
    def __init__(self, key: bytes):
        self.key = key
        self.backend = default_backend()
        self.block_size = algorithms.AES.block_size // 8  

    def encrypt(self, plaintext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()

        pad_len = self.block_size - len(plaintext) % self.block_size
        padded = plaintext + bytes([pad_len] * pad_len)

        result= encryptor.update(padded) + encryptor.finalize()
        print(result)
        return result

    def decrypt(self, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()

        padded = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded[-1]

        result= padded[:-pad_len]
        print(result)
        return result
