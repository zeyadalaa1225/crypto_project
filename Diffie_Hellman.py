import random
from Crypto.Util.number import isPrime

class DiffieHellman:

    def __init__(self, prime=None, generator=None, key_length=1024):
        self.prime = prime
        self.generator = generator
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        
        if self.prime is None:
            self.prime = self._generate_large_prime(key_length)
        if self.generator is None:
            self.generator = self._find_primitive_root(self.prime)
    
    def _generate_large_prime(self, bits):

        while True:
            p = random.getrandbits(bits)
            p |= (1 << bits - 1) | 1  # Set high bit and ensure odd
            
            if isPrime(p):
                print(f"Generated prime: {p}")
                return p
    
    def _find_primitive_root(self, p):
        if p == 2:
            return 1
        
        # Factorize p-1
        phi = p - 1
        factors = self._factorize(phi)
        
        # Test potential generators
        for g in range(2, p):
            if all(pow(g, phi // f, p) != 1 for f in factors):
                print(f"Found generator: {g}")
                return g
        return -1
    
    def _factorize(self, n):

        factors = set()
        while n % 2 == 0:
            factors.add(2)
            n = n // 2
        
        i = 3
        while i * i <= n:
            while n % i == 0:
                factors.add(i)
                n = n // i
            i += 2
        
        if n > 2:
            factors.add(n)
        
        return factors
    
    def generate_keys(self):

        # Private key should be in range [2, p-2]
        self.private_key = random.randint(2, self.prime - 2)
        self.public_key = pow(self.generator, self.private_key, self.prime)
        
        print(f"Generated private key: {self.private_key}")
        print(f"Generated public key: {self.public_key}")
        return self.public_key
    
    def compute_shared_secret(self, other_public_key):

        # Compute shared secret
        self.shared_secret = pow(other_public_key, self.private_key, self.prime)
        
        print(f"Computed shared secret (original): {self.shared_secret}")
        return self.shared_secret  # Return the raw shared secret

