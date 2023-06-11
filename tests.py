from LWE import LWE
from User import User
import numpy as np

class LWE_tests:
    def __init__(self, lwe : LWE):
        self.lwe = lwe
        self.alice = User("Alice", self.lwe)
        self.bob = User("Bob", self.lwe)

    def __send_receive_bits_correct__(self, bits, verbose = False):
        # Alice wants to send bob a message.
        # Encrypt the message using Bob's public key
        enc_msg = self.alice.encrypt(bits, self.bob.public_key)

        # Bob receives a message, and decrypts it using his private key
        dec_msg = self.bob.decrypt(enc_msg)
        if np.array_equal(bits, dec_msg):
            return True
        if verbose:
            diff = np.array(bits) - np.array(dec_msg)
            print(f"Diff: {diff}")
        return False
    
    def __send_receive_bits_incorrect__(self, bits, verbose = False, pub_key = "Alice"):
        # Alice wants to send bob a message.
        # Encrypt the message using ALICE's OWN public key
        # Use Alice's public key by default
        if pub_key == "Alice":
            enc_msg = self.alice.encrypt(bits, self.alice.public_key)
        # Use a function that returns a public_key
        elif callable(pub_key):
            enc_msg = self.alice.encrypt(bits, pub_key())
        # Or use an already existing public key
        else:
            enc_msg = self.alice.encrypt(bits, pub_key)
        # Bob receives a message, and decrypts it using his private key.
        # This should be incorrect
        dec_msg = self.bob.decrypt(enc_msg)
        if np.array_equal(bits, dec_msg):
            return False
        return True

    def test_send_rec_nrounds_correct(self, nrounds = 1000, length = 50, verbose = False):
        nfails = 0
        for i in range(nrounds):
            msg = np.random.randint(0,2,length)
            is_correct = self.__send_receive_bits_correct__(msg, verbose)
            if not is_correct:
                nfails += 1
        return nfails
    
    def test_send_rec_nrounds_incorrect(self, nrounds = 1000, length = 50, verbose = False):
        nfails = 0
        for i in range(nrounds):
            msg = np.random.randint(0,2,length)
            is_incorrect = self.__send_receive_bits_incorrect__(msg, verbose)
            if not is_incorrect:
                nfails += 1
        return nfails
    
    def attempt_multi_cipher_crack(self, lwe_q = None, lwe_n = None, nciphers = 1000, avg_msg_len = 20, verbose=False):
        if lwe_q is None or lwe_n is None:
            lwe = self.lwe
        else:
            lwe = LWE(Q = lwe_q, N = lwe_n)
        if verbose:
            print(f"Attempting to solve LWE with Q = {lwe.Q}, N = {lwe.N} by obtaining multiple ciphertexts")
        alice = User("Alice", lwe)
        # Create a bunch of messages
        plain_texts = np.random.randint(0,2,(nciphers,avg_msg_len))
        # Encrypt them all
        cipher_texts = [alice.encrypt(msg, alice.public_key) for msg in plain_texts]
        # Try to break them all
        dec_msgs = lwe.try_solve_lwe(cipher_texts, verbose = verbose)
        # Check if there are correct decryptions
        cracked = 0
        for plain, dec in zip(plain_texts, dec_msgs):
            if np.array_equal(plain, dec):
                if verbose:
                    print("Found correct decryption!")
                    print(f"Plain: {plain}")
                    print(f"Dec: {dec}")
                cracked += 1
        return cracked
    


    

    
