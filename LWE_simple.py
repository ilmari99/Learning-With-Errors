"""
This program can be used to create a private key, encrypt a message, and decrypt a message using an LWE scheme.
"""

import numpy as np

# Define the parameters for the LWE
M = 7   # Key length
Q = 19  # Modulus for the LWE, Values >= 19 seem to work well. A formula for Q should be used

def __create_private_key__():
    """
    Create a private key of length lambda_
    """
    return np.random.randint(0,Q//2,M)

# Ecrypt a single bit
def __encrypt_bit__(private_key, m):
    """
    Encrypt a single bit
    Enc(sk, m): We will work with the message space M := {0, 1}. Larger message spaces can
    be handled by encrypting each bit of the message independently. The ciphertext is
    c := (a, b) := (a, s^T a + e + m * floor(q/2)* mod q)
    """
    a = np.random.randint(0,Q,M)
    e = np.random.randint(0,2,M)
    b = (private_key @ a + e + m * (Q//2) % Q)
    return (a,b)

def __decrypt_bit__(private_key, c):
    """
    Decrypt a single bit.
    Dec(sk, c): The decryption algorithm is simply
    0 if |b - s^T a mod q| < q/4
    """
    a,b = c
    return 0 if np.linalg.norm(b - private_key @ a) %Q < Q/4 else 1

def __string_to_bits__(string):
    """ Convert a string to a list of bits
    """
    return [int(bit) for byte in string for bit in bin(ord(byte))[2:].zfill(7)]


def __bits_to_string__(binary_list):
    """ Convert a list of bits to a string
    """
    return ''.join([chr(int(''.join([str(bit) for bit in byte]), 2)) for byte in np.split(np.array(binary_list), len(binary_list)/7)])


class User:
    def __init__(self, name):
        self.name = name
        self.public_key = None
        self.private_key = None
        self.error_vector = None
        self.make_private_key()
    
    def make_private_key(self):
        """
        Generate
        """
        self.private_key = __create_private_key__()
    
    def encrypt(self,message):
        """Encrypt an array of bits
        """
        enc_msg = [__encrypt_bit__(self.private_key, m) for m in message]
        return enc_msg
    
    def decrypt(self,enc_msg):
        """Decrypt an array of bits
        """
        dec_msg = [__decrypt_bit__(self.private_key, c) for c in enc_msg]
        return dec_msg

def test_correctness(nrounds = 1000, length = 50, message_space = (0,2), verbose = False):
    is_correct = True
    for i in range(nrounds):
        msg = np.random.randint(message_space[0],message_space[1],length)
        pk = __create_private_key__()
        enc_msg = []
        for b in msg:
            enc_msg.append(__encrypt_bit__(pk, b))
        dec_msg = []
        for c in enc_msg:
            dec_msg.append(__decrypt_bit__(pk, c))
        are_equal = all(dec_msg == msg)
        if not are_equal:
            diff = np.array(dec_msg) - np.array(msg)
            if verbose:
                print("ERROR: Decrypted message != Original message")
                print(f"Diff: {diff}")
            is_correct = False
            break
        if verbose:
            print(f"Decrypted message == Original message: {all(dec_msg == msg)}")
    return is_correct
    
if __name__ == "__main__":
    alice = User("Alice")
    msg = __string_to_bits__("HELLO WORLD!")
    enc_msg = alice.encrypt(msg)
    print(f"Encrypted message: {enc_msg}")
    dec_msg_b = alice.decrypt(enc_msg)
    dec_msg = __bits_to_string__(dec_msg_b)
    print(f"Decrypted message: {dec_msg}")





