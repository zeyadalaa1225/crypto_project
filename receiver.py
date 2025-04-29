import socket
import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from diffie_hellman import DiffieHellman
import hashlib
from hash import HMAC256Messenger
from OTP import OTP
from AES import AESCipher


def receiver():
    HOST = '0.0.0.0'
    PORT = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print("[Receiver] Waiting for connection...")

        conn, addr = s.accept()
        with conn:
            print(f"[Receiver] Connected by {addr}")
            
            # 1. Receive DH parameters
            sender_data = pickle.loads(conn.recv(4096))
            dh = DiffieHellman(prime=sender_data['prime'], 
                              generator=sender_data['generator'])
            dh.generate_keys()
            
            # 2. Send our public key
            conn.sendall(pickle.dumps({'public_key': dh.public_key}))
            
            # 3. Compute shared secret
            shared_secret = dh.compute_shared_secret(sender_data['public_key'])
            print(f"[Receiver] Shared secret: {shared_secret}")
            
            # Convert to AES key
            aes_key = shared_secret.to_bytes(32, byteorder='big')[:32]
            secured_payload = conn.recv(4096)

            # 5. Authenticate using HMAC
            hmac_messenger = HMAC256Messenger(aes_key)
            success, encrypted_seed = hmac_messenger.receiver(secured_payload)

            if not success:
                print("[Receiver] HMAC authentication failed.")
                return

            # 6. Decrypt and display the seed
            aes=AESCipher(aes_key)
            seed = aes.decrypt_message( encrypted_seed)
            print(f"[Receiver] Decrypted seed: {seed.hex()}")
            seed_int = int.from_bytes(seed, byteorder='big') 
            otp=OTP(seed_int)
            
            with open("output.txt", "w") as outfile:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break  # connection closed

                    encrypted_text = pickle.loads(data)
                    message = otp.decrypt(encrypted_text)

                    if message == "__END__":
                        print("[Receiver] End of transmission received.")
                        break

                    print(message)
                    outfile.write(message + '\n')

if __name__ == "__main__":
    receiver()