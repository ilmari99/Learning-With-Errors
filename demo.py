import sys
import numpy as np
from LWE import LWE
from User import User
from tests import LWE_tests

"""
This program demonstrates the implemented LWE scheme, and tests it for correctness
"""

def __string_to_bits__(string):
    """ Convert a string to a list of bits
    """
    return [int(bit) for byte in string for bit in bin(ord(byte))[2:].zfill(7)]


def __bits_to_string__(binary_list):
    """ Convert a list of bits to a string
    """
    return ''.join([chr(int(''.join([str(bit) for bit in byte]), 2)) for byte in np.split(np.array(binary_list), len(binary_list)/7)])

def demo_send_receive():
    lwe = LWE(Q = 1000**3, N = 1000)
    alice = User("Alice", lwe)
    bob = User("Bob", lwe)
    msg = "Hello Bob!"
    print(f"Alice wants to send the message '{msg}' ({sys.getsizeof(msg)}) to Bob")
    msg_bits = __string_to_bits__(msg)
    print(f"Message size ({len(msg_bits)})")
    print("Alice encrypts the message using Bob's public key")

    enc_msg = alice.encrypt(msg_bits, bob.public_key)
    print(f"Encoded message a: {enc_msg[0].shape}, b: {enc_msg[1].shape}")
    print("Bob receives the message, and decrypts it using his private key")

    dec_msg = bob.decrypt(enc_msg)
    #dec_msg = lwe.try_solve_lwe([enc_msg])[0]
    print(f"Decrypted message: {__bits_to_string__(dec_msg)}\n")



if __name__ == "__main__":
    demo_send_receive()
    lwe = LWE(Q = 200**2, N = 200)
    tests = LWE_tests(lwe)
    print("Testing correctness of encryption and decryption...")
    send_rec_failed = tests.test_send_rec_nrounds_correct(nrounds = 100, length = 50, verbose = False)
    print(f"Incorrectly encoded/decoded {send_rec_failed} messages. Expected 0")

    send_rec_success_should_fail = tests.test_send_rec_nrounds_incorrect(nrounds = 100, length = 50, verbose = False)
    print(f"Correctly decoded, when should fail {send_rec_success_should_fail} messages. Expected 0")

    broke_n = tests.attempt_multi_cipher_crack(nciphers=1000, avg_msg_len=50, verbose=False)
    print(f"Correctly broke {broke_n} messages. Expected 0")






