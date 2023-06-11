# LWE IS VERY SENSITIVE TO THE PARAMETERS USED.
# IF THE PARAMETERS ARE NOT CHOSEN CORRECTLY, THE CIPHERTEXT WILL NOT DECRYPT CORRECTLY AND/OR BREAKING THE CIPHERTEXT WILL BE EASY.

import numpy as np
from collections import Counter



class LWE:
    """ A class containing an LWE crypto system functionality.
    This class is used to define the parameters, and use them to encrypt and decrypt messages.

    This is based on this paper in https://people.csail.mit.edu/vinodv/CS294/lecture1.pdf

    The difference in Regev's scheme is that A is NxM
    """
    def __init__(self, N = 300, Q = 104729):
        """ Initialize the LWE crypto system.

        Args:
            N (int, optional): Number of bits in the private key. Defaults to 300.
            Q (int, optional): Modulus for the LWE. Values >= 19 seem to work well. A formula for Q should be used. Defaults to 104729.
            E_BOUNDS (tuple, optional): Bounds for the error distribution. Defaults to (-10,10).
        """
        self.N = N
        self.Q = Q
        err = self.__calc_error_bounds__(Q, N)
        self.rng = np.random.default_rng()
        if err <= 0:
            raise ValueError(f"Error bounds must be positive. Decreare N or increase Q.")
        print(f"Error bounds: {err}")
        self.E_BOUNDS = (-err, err+1)

    def __calc_error_bounds__(self, q, n):
        """ Calculate the error bounds for the LWE scheme, 
        """
        return np.floor(np.sqrt(q/(4*n)))

    def __get_from_error_distribution__(self, sz):
        """ Sample from the error distribution
        """
        # Get integers from a discrete normal between E_BOUNDS[0] and E_BOUNDS[1]
        return self.rng.binomial(self.E_BOUNDS[1] - self.E_BOUNDS[0], 0.5, sz) + self.E_BOUNDS[0]
        #return np.random.randint(self.E_BOUNDS[0], self.E_BOUNDS[1]+1, sz)

    def show_error_distribution(self, n = 10000):
        """ Show the error distribution
        """
        error = self.__get_from_error_distribution__(n)
        c = Counter(error)
        print(f"Error distribution:", end="")
        for k in sorted(c.keys()):
            print(f" {k}:{c[k]}", end="")
        print("")
    
    def __create_private_key__(self):
        """
        Create a private key, which is a vector of size N from the error distribution
        """
        return self.__get_from_error_distribution__(self.N)
    
    def __create_public_key__(self, private_key):
        """
        Let the private key sk be a random vector sk := s ← χ^n chosen from the error distribution
        and the public key is pk := (A, y^T := s^T A + e^T) ∈ Z^(nxn)_q x Z^n_q
        where A is a uniformly random n-by-n matrix and e ← χ^n
        is chosen from the error distribution
        """
        A = np.random.randint(0,self.Q,(self.N,self.N))
        e = self.__get_from_error_distribution__(self.N)
        y = (private_key @ A + e)
        return (A,y)
    
    def keygen(self):
        """
        Create a private key and public key
        """
        private_key = self.__create_private_key__()
        public_key = self.__create_public_key__(private_key)
        return (private_key, public_key)
    
    def __encrypt_bit__(self, public_key, m):
        """
        Encrypt a single bit
        Enc(sk, m): The ciphertext is
        c := (a, b) := (A r + x, y^T r + x' + m * floor(q/2) mod q)
        where r, x ← χ^n and x' ← χ are chosen from the error distribution.
        """
        r = self.__get_from_error_distribution__(self.N)
        x = self.__get_from_error_distribution__(self.N)
        x_prime = self.__get_from_error_distribution__(1)
        A,y = public_key
        a = (A @ r + x)
        b = (y @ r + x_prime + m * (self.Q//2) % self.Q)
        return (a,b)
    
    def __encrypt_multibit__(self, public_key, m):
        """
        Encrypt multiple bits, by computing similarly to a one bit case, but vectorized for multiple bits.
        The output is a and b, where a is an MxN matrix, and b is an Mx1 vector.
        """
        r = self.__get_from_error_distribution__((len(m),self.N))
        x = self.__get_from_error_distribution__((len(m),self.N))
        x_prime = self.__get_from_error_distribution__(len(m))
        x_prime = np.zeros(len(m))
        A,y = public_key
        a = (r @ A.T + x)
        b = (r @ y + x_prime + m * (self.Q//2) % self.Q)
        return (a,b)

    
    def __decrypt_bit__(self, private_key, c):
        """
        Decrypt a single bit.
        Dec(sk, c): The decryption algorithm is simply
        0 if |b - s^T a mod q| < q/4
        """
        a,b = c
        return 0 if np.abs(b - private_key @ a) %self.Q < self.Q/4 else 1
    
    def __decrypt_multibit__(self, private_key, c):
        """ Decrypt a ciphertext encrypted with __encrypt_multibit__. The output should be a list of bits.
        """
        a,b = c
        # a is (MxN), b is (Mx1)
        # Use linear algebra to find which bits are 0 or 1
        temp = np.abs(b - private_key @ a.T) %self.Q - self.Q/4
        # If temp is negative, then the bit is 0, otherwise it is 1
        return [0 if t < 0 else 1 for t in temp]
        #return [0 if np.abs(b[i] - private_key @ a[i,:]) %self.Q < self.Q/4 else 1 for i in range(len(b))]
    
    def try_solve_lwe(self, ciphertexts, verbose = False):
        """ Try to solve the LWE problem with an array of ciphertexts.
        Make the ciphertexts into a matrix A (MxN), and a vector b(M,1).
        Compute the least squares to obtain the private key.
        Use private key to decrypt the ciphertext and return it.
        """
        num_equations = sum([len(c[0]) for c in ciphertexts])
        a = np.zeros((num_equations, self.N))
        b = np.zeros((num_equations, 1))
        if verbose:
            print(f"Number of equations: {num_equations}")
            print(f"Shape of a: {a.shape}, b: {b.shape}")
        for i,c in enumerate(ciphertexts):
            if len(c) != 2:
                raise ValueError("Ciphertexts must be a list of tuples (a,b)")
            a_prime = c[0]
            b_prime = c[1]
            a[i:i+len(a_prime),:] = a_prime
            b[i:i+len(b_prime),:] = b_prime.reshape(-1,1)
            
        sol = np.linalg.lstsq(a, b, rcond=None,)
        if verbose:
            print(f"Residuals: {sol[1]}")

        private_key = sol[0].reshape(-1).astype(int)
        if verbose:
            print(f"Private key: {private_key.shape}")
        plain_texts = [self.__decrypt_multibit__(private_key, c) for c in ciphertexts]
        return plain_texts
        

