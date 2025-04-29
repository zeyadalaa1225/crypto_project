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
        try:
            s.connect((HOST, PORT))
            
            # 1. Send DH parameters and public key
            data = pickle.dumps({
                'prime': dh.prime,
                'generator': dh.generator,
                'public_key': dh.public_key
            })
            # Send length first (4 bytes)
            s.sendall(len(data).to_bytes(4, 'big'))
            # Then send data
            s.sendall(data)
            
            # 2. Receive receiver's public key
            try:
                length_bytes = s.recv(4)
                if not length_bytes:
                    raise ConnectionError("Receiver closed connection unexpectedly")
                length = int.from_bytes(length_bytes, 'big')
                
                receiver_data = b''
                while len(receiver_data) < length:
                    packet = s.recv(length - len(receiver_data))
                    if not packet:
                        raise ConnectionError("Receiver closed connection during data transfer")
                    receiver_data += packet
                
                receiver_data = pickle.loads(receiver_data)
                receiver_public_key = receiver_data['public_key']
                
                # 3. Compute shared secret
                shared_secret = dh.compute_shared_secret(receiver_public_key)
                print(f"[Sender] Shared secret: {shared_secret}")
                # Convert shared secret to 32-byte AES key
                aes_key = shared_secret.to_bytes(32, byteorder='big')[:32]
                
                # 4. Generate and encrypt random seed
                seed = os.urandom(16)
                print("AES Key:", aes_key.hex())
                aes = AESCipher(aes_key)
                encrypted_seed = aes.encrypt_message(seed)
                hmac_messenger = HMAC256Messenger(aes_key)
                secured_payload = hmac_messenger.sender(encrypted_seed)
                
                # Send length first
                s.sendall(len(secured_payload).to_bytes(4, 'big'))
                s.sendall(secured_payload)
                print(f"[Sender] Sent encrypted + HMAC payload")
                print("Seed:", seed.hex())
                
                seed_int = int.from_bytes(seed, byteorder='big') 
                otp = OTP(seed_int)
                
                with open('plaintext.txt', 'r') as f:
                    for line in f:
                        line = line.strip() 
                        if line:  # Skip empty lines
                            encrypted_text = otp.encrypt(line)
                            serialized = pickle.dumps(encrypted_text)
                            # Send length first
                            s.sendall(len(serialized).to_bytes(4, 'big'))
                            s.sendall(serialized)
                
                # Send end marker
                encrypted_text = otp.encrypt("__END__")
                serialized = pickle.dumps(encrypted_text)
                s.sendall(len(serialized).to_bytes(4, 'big'))
                s.sendall(serialized)
                
            except (ConnectionError, pickle.PickleError) as e:
                print(f"[Sender] Error during communication: {e}")
                
        except ConnectionRefusedError:
            print("[Sender] Connection refused. Is the receiver running?")
        except Exception as e:
            print(f"[Sender] Unexpected error: {e}")
if __name__ == "__main__":
    sender()