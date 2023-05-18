"""
This program can be used to create a private and public key, and send encrypted messages between Alice and Bob with the LWE cryptosystem.
"""
import numpy as np

# LWE IS VERY SENSITIVE TO THE PARAMETERS USED.
# IF THE PARAMETERS ARE NOT CHOSEN CORRECTLY, THE CIPHERTEXT WILL NOT DECRYPT CORRECTLY AND/OR BREAKING THE CIPHERTEXT WILL BE EASY.

# Define the parameters for the LWE
# TODO: What should these be?
N = 300   # Number of bits in the private key and error vector
M = 200   # Number of vectors in the public key
# Modulus for the LWE, Values >= 19 seem to work well. A formula for Q should be used
# TODO: What should the modulus be?
Q = 104729
# TODO: What should the error distribution be?
E_BOUNDS = (-10,10)


def __get_from_error_distribution__(sz):
    """ Sample from the error distribution
    """
    return np.random.randint(E_BOUNDS[0], E_BOUNDS[1]+1, sz)

def __create_private_key__():
    """
    Create a private key, which is a vector of size N from the error distribution
    """
    return __get_from_error_distribution__(N)

def __create_public_key__(private_key):
    """
    Let the private key sk be a random vector sk := s ← χ^n chosen from the error distribution
    and the public key is pk := (A, y^T := s^T A + e^T) ∈ Z^(nxn)_q x Z^n_q
    where A is a uniformly random n-by-n matrix and e ← χ^n
    is chosen from the error distribution
    """
    A = __get_from_error_distribution__((N,N))
    e = __get_from_error_distribution__(N)
    y = (private_key @ A + e)
    return (A,y)

def __keygen__():
    """
    Create a private key and public key
    """
    private_key = __create_private_key__()
    public_key = __create_public_key__(private_key)
    return (private_key, public_key)

# Encrypt a single bit
def __encrypt_bit__(public_key, m):
    """
    Encrypt a single bit
    Enc(sk, m): The ciphertext is
    c := (a, b) := (A r + x, y^T r + x' + m * floor(q/2) mod q)
    where r, x ← χ^n and x' ← χ are chosen from the error distribution.
    """
    r = __get_from_error_distribution__(N)
    x = __get_from_error_distribution__(N)
    x_prime = __get_from_error_distribution__(1)
    A,y = public_key
    a = (A @ r + x)
    b = (y @ r + x_prime + m * (Q//2) % Q)
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
        self.private_key, self.public_key = __keygen__()
    
    def encrypt(self,message, public_key):
        """Encrypt using someones public key
        """
        enc_msg = [__encrypt_bit__(public_key, m) for m in message]
        return enc_msg
    
    def decrypt(self,enc_msg):
        """Decrypt an array of bits, using my private key
        """
        dec_msg = [__decrypt_bit__(self.private_key, c) for c in enc_msg]
        return dec_msg

def run_bit_test(nrounds= 1000, length = 50, verbose = False):
    """Run a test to see if the encryption and decryption works
    """
    for i in range(nrounds):
        bits = np.random.randint(0,2,length)
        is_correct = send_receive_bits_correct(bits,verbose=verbose)
        if verbose:
            print(f"Round {i} correct: {is_correct}")
        if not is_correct:
            return False
    return True

def run_string_test(nrounds= 1000, length = (1,40), verbose = False):
    """Run a test to see if the encryption and decryption works
    """
    if isinstance(length, tuple):
        length_fun = lambda : np.random.randint(length)[-1]
    else:
        length_fun = lambda : length
    
    for i in range(nrounds):
        str_length = length_fun()
        string = ''.join([chr(np.random.randint(0,128)) for _ in range(str_length)])
        bits = __string_to_bits__(string)
        is_correct = send_receive_bits_correct(bits)
        if verbose:
            print(f"{string}: {is_correct}")
        if not is_correct:
            return False
    return True

def should_be_incorrect():
    alice = User("Alice")
    bob = User("Bob")
    msg = np.random.randint(0,2,10)

    # Alice wants to send bob a message.
    # Encrypt the message using ALICE's OWN public key
    enc_msg = alice.encrypt(msg, alice.public_key)

    # Bob receives a message, and decrypts it using his private key.
    # This should be incorrect
    dec_msg = bob.decrypt(enc_msg)
    if np.array_equal(msg, dec_msg):
        return True
    return False

def send_receive_bits_correct(bits, verbose = False):
    alice = User("Alice")
    bob = User("Bob")
    # Alice wants to send bob a message.
    # Encrypt the message using Bob's public key
    enc_msg = alice.encrypt(bits, bob.public_key)

    # Bob receives a message, and decrypts it using his private key
    dec_msg = bob.decrypt(enc_msg)
    if np.array_equal(bits, dec_msg):
        return True
    if verbose:
        diff = np.array(bits) - np.array(dec_msg)
        print(f"Diff: {diff}")
    return False
    
if __name__ == "__main__":
    for i in range(10):
        is_eq = should_be_incorrect()
        print(f"Should be False: {is_eq}")
    print()
    run_bit_test(nrounds=100,length=10,verbose=True)
    #run_string_test(nrounds=10,verbose=True)






