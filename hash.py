import hmac
import hashlib

class HMAC256Messenger:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
        self.HMAC_SIZE = hashlib.sha256().digest_size  # 32 bytes

    def hmac256(self, message: bytes) -> bytes:
        return hmac.new(self.secret_key, message, hashlib.sha256).digest()

    def sender(self, message: bytes) -> bytes:
        hmac_hash = self.hmac256(message)
        return message + hmac_hash

    def receiver(self, data: bytes) -> (bool, bytes):
        if len(data) < self.HMAC_SIZE:
            print("Invalid data: too short to contain valid HMAC.")
            return False, b""

        message = data[:-self.HMAC_SIZE]
        received_hash = data[-self.HMAC_SIZE:]
        expected_hash = self.hmac256(message)

        if hmac.compare_digest(expected_hash, received_hash):
            print("Message authenticated successfully!")
            return True, message
        else:
            print("Authentication failed! HMAC does not match.")
            return False, b""
