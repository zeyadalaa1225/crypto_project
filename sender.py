import socket
import pickle
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from diffie_hellman import DiffieHellman
import hashlib
from hash import HMAC256Messenger
from OTP import OTP
from AES import AESCipher


def sender():
    HOST = '127.0.0.1'
    PORT = 12345

    # Initialize DH and generate parameters
    dh = DiffieHellman(key_length=8)
    dh.generate_keys()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        # 1. Send DH parameters and public key
        s.sendall(pickle.dumps({
            'prime': dh.prime,
            'generator': dh.generator,
            'public_key': dh.public_key
        }))
        
        # 2. Receive receiver's public key
        receiver_data = pickle.loads(s.recv(4096))
        receiver_public_key = receiver_data['public_key']
        # 3. Compute shared secret
        shared_secret = dh.compute_shared_secret(receiver_public_key)
        print(f"[Sender] Shared secret: {shared_secret}")
        # Convert shared secret to 32-byte AES key
        aes_key = shared_secret.to_bytes(32, byteorder='big')[:32]  # Use first 32 bytes
        # 4. Generate and encrypt random seed
        seed = os.urandom(16)  # 16-byte random seed
        print(aes_key)
        aes=AESCipher(aes_key)
        encrypted_seed = aes.encrypt_message( seed)
        hmac_messenger = HMAC256Messenger(aes_key)
        secured_payload = hmac_messenger.sender(encrypted_seed)
        s.sendall(secured_payload)
        print(f"[Sender] Sent encrypted + HMAC payload")
        print(seed.hex())
        seed_int = int.from_bytes(seed, byteorder='big') 
        otp=OTP(seed_int)
        with open('plaintext.txt', 'r') as f:
            for line in f:
                line = line.strip() 
                encrypted_text=otp.encrypt(line)
                print(encrypted_text)
                serialized = pickle.dumps(encrypted_text)
                s.sendall(serialized)
                print(serialized.hex())
        encrypted_text=otp.encrypt("__END__")
        serialized = pickle.dumps(encrypted_text)
        s.sendall(serialized)

if __name__ == "__main__":
    sender()