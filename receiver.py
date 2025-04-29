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
            
            try:
                # 1. Receive DH parameters
                length_bytes = conn.recv(4)
                if not length_bytes:
                    raise ConnectionError("Sender closed connection unexpectedly")
                length = int.from_bytes(length_bytes, 'big')
                
                sender_data = b''
                while len(sender_data) < length:
                    packet = conn.recv(length - len(sender_data))
                    if not packet:
                        raise ConnectionError("Sender closed connection during data transfer")
                    sender_data += packet
                
                sender_data = pickle.loads(sender_data)
                
                dh = DiffieHellman(prime=sender_data['prime'], 
                                 generator=sender_data['generator'])
                dh.generate_keys()
                
                # 2. Send our public key
                data = pickle.dumps({'public_key': dh.public_key})
                conn.sendall(len(data).to_bytes(4, 'big'))
                conn.sendall(data)
                
                # 3. Compute shared secret
                shared_secret = dh.compute_shared_secret(sender_data['public_key'])
                print(f"[Receiver] Shared secret: {shared_secret}")
                
                # Convert to AES key
                aes_key = shared_secret.to_bytes(32, byteorder='big')[:32]
                print("AES Key:", aes_key.hex())
                
                # Receive secured payload length
                length_bytes = conn.recv(4)
                if not length_bytes:
                    raise ConnectionError("Sender closed connection unexpectedly")
                length = int.from_bytes(length_bytes, 'big')
                
                secured_payload = b''
                while len(secured_payload) < length:
                    packet = conn.recv(length - len(secured_payload))
                    if not packet:
                        raise ConnectionError("Sender closed connection during data transfer")
                    secured_payload += packet

                # 5. Authenticate using HMAC
                hmac_messenger = HMAC256Messenger(aes_key)
                success, encrypted_seed = hmac_messenger.receiver(secured_payload)

                if not success:
                    print("[Receiver] HMAC authentication failed.")
                    return

                # 6. Decrypt and display the seed
                aes = AESCipher(aes_key)
                seed = aes.decrypt_message(encrypted_seed)
                print(f"[Receiver] Decrypted seed: {seed.hex()}")
                seed_int = int.from_bytes(seed, byteorder='big') 
                otp = OTP(seed_int)
                
                with open("output.txt", "w") as outfile:
                    while True:
                        # Get message length first
                        length_bytes = conn.recv(4)
                        if not length_bytes:
                            print("[Receiver] Connection closed by sender")
                            break
                        length = int.from_bytes(length_bytes, 'big')
                        
                        data = b''
                        while len(data) < length:
                            packet = conn.recv(length - len(data))
                            if not packet:
                                raise ConnectionError("Sender closed connection during data transfer")
                            data += packet
                        
                        encrypted_text = pickle.loads(data)
                        message = otp.decrypt(encrypted_text)

                        if message == "__END__":
                            print("[Receiver] End of transmission received.")
                            break

                        outfile.write(message + '\n')
                        
            except (ConnectionError, pickle.PickleError) as e:
                print(f"[Receiver] Error during communication: {e}")
            except Exception as e:
                print(f"[Receiver] Unexpected error: {e}")
if __name__ == "__main__":
    receiver()