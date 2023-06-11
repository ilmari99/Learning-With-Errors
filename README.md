# Learning with Errors
The goal of this project is to get familiar with the Learning With Errors (LWE) cryptosystem.
LWE is the basis for many of the most prominent post-quantum encryption
algorithms.
Conceptually, the logic behind the secrecy of LWE is based on representing a secret
as a set of linear equations containing noise. This problem can also be viewed as a
lattice problem (namely shortest vector problem (SVP)), which is known to be NP-hard and
there is no known polynomial time quantum algorithm either.
In the report, I will introduce the basic concepts and math behind LWE, and describe
a simple public key system utilizing the LWE problem.