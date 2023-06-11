import numpy as np
from LWE import LWE

class User:
    def __init__(self, name, lwe : LWE):
        self.name = name
        self.lwe = lwe
        self.private_key, self.public_key = self.lwe.keygen()
    
    def encrypt(self,message, public_key):
        """Encrypt a list of bits
        """
        #enc_msg = [self.lwe.__encrypt_bit__(public_key, m) for m in message]
        enc_msg = self.lwe.__encrypt_multibit__(public_key, np.array(message))
        return enc_msg
    
    def decrypt(self,enc_msg):
        """Decrypt a list of bits, using my private key
        """
        #dec_msg = [self.lwe.__decrypt_bit__(self.private_key, c) for c in enc_msg]
        dec_msg = self.lwe.__decrypt_multibit__(self.private_key, enc_msg)
        return dec_msg