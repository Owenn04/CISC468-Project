from sympy import *

p = 157
alpha = 5
x = 110
d = 36
i = 98

# compute public key component beta = alpha^d mod p
beta = pow(alpha, d, p)

# compute ciphertext components
c1 = pow(alpha, i, p)
c2 = (x * pow(beta, i, p)) % p

print("beta =", beta)
print("c1 =", c1)
print("c2 =", c2)
print("ciphertext =", (c1, c2))