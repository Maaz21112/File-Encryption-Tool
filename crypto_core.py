from Crypto.Cipher import AES, DES3, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import os

class FileCrypto:
    def __init__(self, password, algorithm='AES'):
        self.algorithm = algorithm.upper()
        self.key = self._derive_key(password)
        
    def _derive_key(self, password):
        # Key derivation using SHA-256
        if self.algorithm == 'AES':
            key_size = 32  # 256 bits
        elif self.algorithm == 'DES3':
            key_size = 24  # 168 bits (24 bytes)
        elif self.algorithm == 'DES':
            key_size = 8   # 56 bits
        else:
            raise ValueError("Unsupported algorithm")
            
        return hashlib.sha256(password.encode()).digest()[:key_size]

    def encrypt_file(self, input_file, output_file):
        iv = get_random_bytes(16 if self.algorithm == 'AES' else 8)
        
        if self.algorithm == 'AES':
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
        elif self.algorithm == 'DES3':
            cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        elif self.algorithm == 'DES':
            cipher = DES.new(self.key, DES.MODE_CBC, iv)
            
        with open(input_file, 'rb') as fin:
            plaintext = fin.read()
            
        padded_data = pad(plaintext, cipher.block_size)
        ciphertext = iv + cipher.encrypt(padded_data)
        
        with open(output_file, 'wb') as fout:
            fout.write(ciphertext)

    def decrypt_file(self, input_file, output_file):
        with open(input_file, 'rb') as fin:
            ciphertext = fin.read()
            
        iv = ciphertext[:16 if self.algorithm == 'AES' else 8]
        ciphertext = ciphertext[len(iv):]
        
        if self.algorithm == 'AES':
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
        elif self.algorithm == 'DES3':
            cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        elif self.algorithm == 'DES':
            cipher = DES.new(self.key, DES.MODE_CBC, iv)
            
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size)
        
        with open(output_file, 'wb') as fout:
            fout.write(plaintext)